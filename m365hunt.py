#!/usr/bin/env python3
"""
m365hunt - Microsoft 365 / Entra identity reconnaissance & tenant posture
=========================================================================
Three credential-free operations against a domain and its users:

  * enum     : does a Microsoft 365 / Entra account EXIST (personal vs
               organizational)? Optionally infer each account's sign-in methods.
  * identity : the full picture of a domain — sovereign cloud, Entra tenant GUID
               and region, Managed vs Federated (+ the federation IdP and ADFS
               version), Seamless SSO, legacy-auth reachability, advertised
               sign-in methods, the mailbox provider, and the whole identity
               footprint + federation-trust map across the tenant.
  * format   : infer the organisation's username convention (first.last, flast,
               …) from known names, or apply a known one, and build an address
               list for enumeration.

No real password is ever transmitted — existence probes send a random throwaway.

The enumeration engine is deliberately *not* a menu of modules. For each domain
it fingerprints the tenant once, then checks every identity against independent
Microsoft surfaces and decides the verdict itself:

  - GetCredentialType  (IfExistsResult)     — primary (existence + account type)
  - OAuth2 ROPC        (AADSTS error codes)  — fallback when GCT is inconclusive

Each hit is classified personal (consumer MSA) or organizational (Entra tenant).
Non-Microsoft domains are reported with their configured provider; their account
existence is not guessed.

author: black3dm0nd - https://black3dm0nd.com
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import random
import re
import secrets
import ssl
import string
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict

try:
    import httpx
except ImportError:
    sys.exit("missing dependency: pip install httpx")


class C:
    G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; B = "\033[94m"
    C_ = "\033[96m"; DIM = "\033[2m"; BOLD = "\033[1m"; X = "\033[0m"


_DBG = {"on": False}


def _dbg(*a) -> None:
    if _DBG["on"]:
        print(f"{C.DIM}[debug]", *a, C.X)


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


def _ua() -> str:
    return random.choice(USER_AGENTS)


def _throwaway() -> str:
    """A random value used in place of a password while probing existence, so a
    real credential is never transmitted."""
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(18))


# GetCredentialType IfExistsResult values meaning "account present".
#   0 exists · 5 exists (different identity provider) · 6 exists (both)
_GCT_EXISTS = {0, 5, 6}

# AADSTS codes that confirm a user EXISTS (the credential reached a real
# identity: wrong/expired password, MFA, lockout, disabled, conditional access).
AADSTS_VALID_USER = {
    "50126", "50053", "50055", "50057", "50072", "50074",
    "50076", "50079", "53003", "53004", "700016",
}
AADSTS_INVALID_USER = {"50034"}         # user does not exist in the directory
AADSTS_NO_TENANT = {"50059", "90002"}   # tenant / domain not found

M365_CLOUDS: list[tuple[str, str]] = [
    ("Commercial (Worldwide)", "login.microsoftonline.com"),
    ("US Gov (GCC High / DoD)", "login.microsoftonline.us"),
    ("China (21Vianet)", "login.partner.microsoftonline.cn"),
]
AUTOD_SVC: dict[str, str] = {
    "login.microsoftonline.com": "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
    "login.microsoftonline.us": "https://autodiscover-s.office365.us/autodiscover/autodiscover.svc",
    "login.partner.microsoftonline.cn": "https://autodiscover-s.partner.outlook.cn/autodiscover/autodiscover.svc",
}
TOKEN_URL = {
    "login.microsoftonline.com": "https://login.microsoftonline.com/common/oauth2/token",
    "login.microsoftonline.us": "https://login.microsoftonline.us/common/oauth2/token",
    "login.partner.microsoftonline.cn": "https://login.partner.microsoftonline.cn/common/oauth2/token",
}


def _ordered_hosts(login_host: str) -> list[str]:
    """Candidate login hosts, the detected cloud first, then the rest — so a probe
    falls through to US-Gov / China when the primary cloud doesn't host the user."""
    allh = [h for _, h in M365_CLOUDS]
    primary = login_host if login_host in allh else allh[0]
    return [primary] + [h for h in allh if h != primary]
# Azure AD Graph client used for the resource-owner password-grant probe.
OAUTH2_CLIENT_ID = "1b730954-1685-4b74-9bfd-dae224f7355f"
OAUTH2_RESOURCE = "https://graph.windows.net"

_FED_ACTION = ("http://schemas.microsoft.com/exchange/2010/Autodiscover/"
               "Autodiscover/GetFederationInformation")
_FED_SOAP = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:a="http://www.w3.org/2005/08/addressing"
 xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <a:Action soap:mustUnderstand="1">{action}</a:Action>
    <a:To soap:mustUnderstand="1">{to}</a:To>
    <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
  </soap:Header>
  <soap:Body>
    <GetFederationInformationRequestMessage
      xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Request><Domain>{domain}</Domain></Request>
    </GetFederationInformationRequestMessage>
  </soap:Body>
</soap:Envelope>"""

# MX host substring -> mailbox provider (identity reporting only).
MX_PROVIDERS = [
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("outlook.com", "Microsoft 365"),
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("pphosted.com", "Proofpoint (fronting)"),
    ("ppe-hosted.com", "Proofpoint (fronting)"),
    ("mimecast.com", "Mimecast (fronting)"),
    ("barracudanetworks.com", "Barracuda (fronting)"),
    ("messagelabs.com", "Symantec.cloud (fronting)"),
    ("secureserver.net", "GoDaddy"),
    ("zoho.com", "Zoho Mail"),
    ("yandex.net", "Yandex"),
    ("qq.com", "Tencent"),
]


# --------------------------------------------------------------------------- #
# Shared infrastructure
# --------------------------------------------------------------------------- #
class Pacer:
    """Jittered minimum-interval limiter shared across workers."""
    def __init__(self, rate: float):
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.jitter = self.interval * 0.3
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next - now) + random.uniform(0, self.jitter)
            self._next = max(now, self._next) + self.interval
        if delay:
            await asyncio.sleep(delay)


async def doh(client: httpx.AsyncClient, name: str, rtype: str) -> list[str]:
    try:
        r = await client.get("https://cloudflare-dns.com/dns-query",
                             params={"name": name, "type": rtype},
                             headers={"accept": "application/dns-json"})
        if r.status_code != 200:
            return []
        return [a.get("data", "").strip('"') for a in r.json().get("Answer", [])]
    except (httpx.HTTPError, json.JSONDecodeError):
        return []


async def resolve_mx(client: httpx.AsyncClient, domain: str) -> list[str]:
    hosts = []
    for rec in await doh(client, domain, "MX"):
        parts = rec.split()
        hosts.append((parts[-1] if parts else rec).rstrip(".").lower())
    return hosts


def _aadsts(text: str) -> str | None:
    i = text.find("AADSTS")
    return text[i + 6:i + 11] if i != -1 else None


# Consumer (personal) Microsoft account domains.
_CONSUMER_FIRST = {"outlook", "hotmail", "live", "msn"}
_CONSUMER_EXACT = {"passport.com", "windowslive.com", "live.com", "msn.com"}


def _is_consumer_domain(domain: str) -> bool:
    first = domain.split(".", 1)[0]
    return first in _CONSUMER_FIRST or domain in _CONSUMER_EXACT


# =========================================================================== #
# IDENTITY & POSTURE  (tenant / realm / provider discovery + security posture)
# =========================================================================== #
@dataclass
class DomainCtx:
    domain: str
    tenant: bool = False
    cloud: str = ""
    login_host: str = "login.microsoftonline.com"
    tenant_id: str = ""
    realm: str = ""                 # Managed | Federated | Unknown
    federation_url: str = ""        # ADFS STS endpoint (AuthURL)
    brand: str = ""
    region: str = ""                # tenant_region_scope
    onmicrosoft: str = ""
    tenant_domains: list[str] = field(default_factory=list)
    provider: str = ""              # mailbox provider from MX
    mailbox_host: str = ""
    # --- security posture (filled only when want_posture) ---------------------
    desktop_sso: str = ""           # Seamless SSO (DesktopSsoEnabled)
    idp_vendor: str = ""            # federation IdP fingerprint
    idp_version: str = ""           # AD FS version, when detectable
    legacy_auth: str = ""           # WS-Trust usernamemixed reachability
    auth_methods: list[str] = field(default_factory=list)
    error: str = ""


async def enum_tenant_domains(client: httpx.AsyncClient, domain: str,
                              login_host: str) -> list[str]:
    svc = AUTOD_SVC.get(login_host, AUTOD_SVC["login.microsoftonline.com"])
    body = _FED_SOAP.format(action=_FED_ACTION, to=svc, domain=domain)
    headers = {"Content-Type": "text/xml; charset=utf-8",
               "SOAPAction": f'"{_FED_ACTION}"', "User-Agent": "AutodiscoverClient"}
    try:
        r = await client.post(svc, content=body, headers=headers)
        if r.status_code != 200:
            return []
        root = ET.fromstring(r.text)
    except (httpx.HTTPError, ET.ParseError):
        return []
    return sorted({el.text.strip().lower() for el in root.iter()
                   if el.tag.split("}")[-1] == "Domain" and el.text and "." in el.text})


async def build_context(client: httpx.AsyncClient, domain: str, want_mx: bool = True,
                        want_domains: bool = True, want_posture: bool = False) -> DomainCtx:
    """Resolve everything known about a domain in one pass. enum passes
    want_mx/want_domains False to stay fast (cloud + realm only); the full
    report additionally passes want_posture for the security-posture signals."""
    ctx = DomainCtx(domain=domain)
    # 1) authoritative cloud + realm: getuserrealm across every sovereign cloud.
    #    The cloud that answers Managed/Federated (not "Unknown") is the real one —
    #    this is what correctly places GCC High / DoD tenants on
    #    login.microsoftonline.us and China tenants on the .cn cloud, instead of
    #    assuming commercial.
    for cloud_name, host in M365_CLOUDS:
        try:
            r = await client.get(f"https://{host}/getuserrealm.srf",
                                 params={"login": f"user@{domain}", "json": "1"})
            if r.status_code != 200:
                continue
            j = r.json()
            ns = j.get("NameSpaceType", "") or ""
            if ns in ("Managed", "Federated"):
                ctx.tenant, ctx.cloud, ctx.login_host = True, cloud_name, host
                ctx.realm = ns
                ctx.federation_url = j.get("AuthURL", "") or ""
                ctx.brand = j.get("FederationBrandName", "") or ""
                break
        except (httpx.HTTPError, json.JSONDecodeError):
            continue
    # 2) tenant GUID + region + tenant-domain list (full report only — skipped for
    #    speed during enum, which only needs the cloud/realm from step 1)
    if ctx.tenant and (want_domains or want_posture):
        try:
            r = await client.get(
                f"https://{ctx.login_host}/{domain}/v2.0/.well-known/openid-configuration")
            if r.status_code == 200:
                j = r.json()
                ctx.region = j.get("tenant_region_scope", "") or ""
                for p in j.get("issuer", "").split("/"):
                    if len(p) == 36 and p.count("-") == 4:
                        ctx.tenant_id = p
                        break
        except (httpx.HTTPError, json.JSONDecodeError):
            pass
    if ctx.tenant and want_domains:
        doms = await enum_tenant_domains(client, domain, ctx.login_host)
        if doms:
            ctx.tenant_domains = doms
            onm = [d for d in doms
                   if d.endswith((".onmicrosoft.com", ".onmicrosoft.us")) and ".mail." not in d]
            if onm:
                ctx.onmicrosoft = onm[0]
    # 2b) security posture — Seamless SSO, advertised methods, IdP + legacy auth
    if ctx.tenant and want_posture:
        gct = await _gct_fetch(client, f"{secrets.token_hex(4)}@{domain}", ctx)
        if gct:
            dsso = (gct.get("EstsProperties", {}) or {}).get("DesktopSsoEnabled")
            ctx.desktop_sso = {True: "enabled", False: "disabled"}.get(dsso, "indeterminate")
            ctx.auth_methods = _auth_methods(gct)
        if ctx.realm == "Federated" and ctx.federation_url:
            ctx.idp_vendor = _idp_vendor(ctx.federation_url)
            ctx.idp_version, ctx.legacy_auth = await _adfs_probe(client, ctx.federation_url)
        elif ctx.realm == "Managed":
            ctx.idp_vendor = "Entra ID (cloud-managed)"
            ctx.legacy_auth = "indeterminate (managed — needs authenticated test)"
    # 3) mailbox provider from MX. A known MX wins; otherwise an Entra tenant
    #    (Exchange Online is provisioned for every tenant) is Microsoft 365 even
    #    when inbound mail is routed through an unrecognised gateway — so a real
    #    M365 org is never mislabelled "Self-hosted / other".
    if want_mx:
        mx = await resolve_mx(client, domain)
        ctx.mailbox_host = mx[0] if mx else ""
        for sub, prov in MX_PROVIDERS:
            if any(sub in h for h in mx):
                ctx.provider = prov
                break
        if not ctx.provider:
            if ctx.tenant:
                ctx.provider = "Microsoft 365"
            elif mx:
                ctx.provider = "Self-hosted / other"
            else:
                ctx.provider = "Unknown"
    return ctx


def _is_microsoft(ctx: DomainCtx) -> bool:
    return ctx.tenant or "Microsoft" in ctx.provider


def _classify(dom: str, code, unmanaged: bool, ctx: DomainCtx) -> str:
    """personal | organizational | both — from the GetCredentialType signals."""
    if _is_consumer_domain(dom):
        return "personal"
    if code == 6:
        return "both"
    if code == 5:                                   # exists via a different IdP
        return "organizational" if ctx.realm == "Federated" else "personal"
    if code == 0:
        return "organizational"
    return "organizational" if ctx.tenant else ""


# =========================================================================== #
# INTELLIGENCE HELPERS  (sign-in methods, IdP vendor, ADFS — all credential-free)
# =========================================================================== #
_GCT_BODY = {"isOtherIdpSupported": True, "checkPhones": False,
             "isRemoteNGCSupported": True, "isCookieBannerShown": False,
             "isFidoSupported": True, "originalRequest": "", "flowToken": ""}


async def _gct_fetch(cl, email: str, ctx: DomainCtx) -> dict | None:
    """Raw GetCredentialType JSON for a user, from the tenant's cloud. No password."""
    for host in _ordered_hosts(ctx.login_host):
        url = f"https://{host}/common/GetCredentialType?mkt=en-US"
        try:
            r = await cl.post(url, json={"username": email, **_GCT_BODY},
                              headers={"User-Agent": _ua(), "Accept": "application/json",
                                       "Referer": f"https://{host}/"})
            data = r.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            return data
    return None


def _auth_methods(gct: dict | None) -> list[str]:
    """Sign-in methods the directory advertises for a user, read from the
    GetCredentialType Credentials block — inferred, never authenticated."""
    c = (gct or {}).get("Credentials", {}) or {}
    out: list[str] = []
    if c.get("HasPassword"):
        out.append("password")
    if c.get("RemoteNgcParams"):
        out.append("Authenticator (passwordless)")
    if c.get("FidoParams"):
        out.append("FIDO2 / passkey")
    if c.get("CertAuthParams"):
        out.append("certificate (PKI)")
    if c.get("SasParams"):
        out.append("SMS / voice OTP")
    if c.get("GoogleParams"):
        out.append("Google federation")
    if c.get("FacebookParams"):
        out.append("Facebook federation")
    if c.get("FederationRedirectUrl"):
        out.append("federated IdP redirect")
    return out


_IDP_SIGNS = [
    ("okta", "Okta"), ("pingidentity", "PingFederate"), ("pingone", "PingOne"),
    ("onelogin", "OneLogin"), ("auth0.com", "Auth0"),
    ("accounts.google.com", "Google Workspace"), ("duosecurity", "Cisco Duo"),
    ("login.microsoftonline.com", "Entra ID"), ("microsoftonline.us", "Entra ID (US Gov)"),
    ("microsoftonline.cn", "Entra ID (21Vianet)"),
]


def _idp_vendor(url: str) -> str:
    """Name the identity provider a federation AuthURL points to."""
    low = (url or "").lower()
    if "/adfs/" in low or low.startswith("https://sts.") or ".sts." in low:
        return "AD FS (on-prem)"
    for sign, name in _IDP_SIGNS:
        if sign in low:
            return name
    m = re.search(r"https?://([^/]+)", low)
    return (m.group(1) if m else "") or "unknown"


async def _adfs_probe(cl, auth_url: str) -> tuple[str, str]:
    """For a federated IdP, return (version/vendor, legacy-auth reachability) —
    read from published endpoints, no credentials sent."""
    vendor = _idp_vendor(auth_url)
    m = re.search(r"https?://([^/]+)", auth_url or "")
    host = m.group(1) if m else ""
    if not host:
        return vendor, "indeterminate"
    legacy = "usernamemixed not published"
    for path in ("/adfs/services/trust/13/usernamemixed",
                 "/adfs/services/trust/2005/usernamemixed"):
        try:
            r = await cl.get(f"https://{host}{path}", headers={"User-Agent": _ua()})
            if r.status_code in (200, 400, 405):
                legacy = "WS-Trust usernamemixed published (legacy auth reachable)"
                break
        except httpx.HTTPError:
            continue
    version = vendor
    if "adfs" in (auth_url or "").lower():
        try:
            r = await cl.get(auth_url, headers={"User-Agent": _ua()})
            mv = (re.search(r"/adfs/portal/[^\"']*?(\d+\.\d+\.\d+\.\d+)", r.text)
                  or re.search(r"HostName=[^;]+;Version=(\d+\.\d+\.\d+\.\d+)", r.text))
            version = f"AD FS ({mv.group(1)})" if mv else "AD FS (version undetermined)"
        except httpx.HTTPError:
            version = "AD FS (version undetermined)"
    return version, legacy


# =========================================================================== #
# EXISTENCE PROBES  (no real password is transmitted)
# =========================================================================== #
async def _probe_gct(cl, email, ctx: DomainCtx) -> tuple[str, str, str, list]:
    """GetCredentialType — one request that yields existence AND account type.
    Returns (verdict, kind, detail, auth_methods)."""
    dom = email.split("@", 1)[1]
    body = {"username": email, **_GCT_BODY}
    saw_notexist, last = False, ("unknown", "", "inconclusive response", [])
    for host in _ordered_hosts(ctx.login_host):
        url = f"https://{host}/common/GetCredentialType?mkt=en-US"
        try:
            r = await cl.post(url, json=body, headers={"User-Agent": _ua(),
                              "Accept": "application/json", "Referer": f"https://{host}/"})
            data = r.json()
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            last = ("unknown", "", "request error", [])
            _dbg(f"gct {host} {email} -> error {str(e)[:60]}")
            continue
        if data.get("ThrottleStatus", 0) not in (0, None):
            last = ("unknown", "", "rate-limited by the endpoint", [])
            continue
        code = data.get("IfExistsResult")
        unmanaged = bool(data.get("IsUnmanaged"))
        _dbg(f"gct {host} {email} -> IfExistsResult={code} IsUnmanaged={unmanaged}")
        kind = _classify(dom, code, unmanaged, ctx)
        if code in _GCT_EXISTS:
            return "exist", kind, "", _auth_methods(data)
        if code == 1:
            saw_notexist, last = True, ("notexist", "", "", [])
            continue
        last = ("unknown", "", "inconclusive response", [])
    return ("notexist", "", "", []) if saw_notexist else last


async def _probe_oauth2(cl, email, ctx: DomainCtx) -> tuple[str, str]:
    data = {"resource": OAUTH2_RESOURCE, "client_id": OAUTH2_CLIENT_ID,
            "client_info": "1", "grant_type": "password",
            "username": email, "password": _throwaway(), "scope": "openid"}
    saw_notexist, last = False, ("unknown", "inconclusive response")
    for host in _ordered_hosts(ctx.login_host):
        try:
            r = await cl.post(TOKEN_URL[host], data=data, headers={"User-Agent": _ua(),
                              "Accept": "application/json"})
            text = r.text
        except httpx.HTTPError as e:
            last = ("unknown", "request error")
            _dbg(f"oauth2 {host} {email} -> error {str(e)[:60]}")
            continue
        code = _aadsts(text)
        _dbg(f"oauth2 {host} {email} -> HTTP {r.status_code} AADSTS{code}")
        if r.status_code == 200 and "access_token" in text:
            return "exist", ""
        if code in AADSTS_VALID_USER:
            return "exist", ""
        if code in AADSTS_INVALID_USER:
            saw_notexist, last = True, ("notexist", "")
            continue
        if code in AADSTS_NO_TENANT:
            last = ("unknown", "inconclusive response")
            continue
        last = ("unknown", "inconclusive response")
    return ("notexist", "") if saw_notexist else last


# =========================================================================== #
# DECISION ENGINE
# =========================================================================== #
@dataclass
class Result:
    user: str
    status: str                     # VALID | INVALID | UNKNOWN
    detail: str = ""
    kind: str = ""                  # personal | organizational | both
    methods: list = field(default_factory=list)   # advertised sign-in methods

    def row(self, with_methods: bool = False) -> dict:
        d = {"user": self.user, "status": self.status, "kind": self.kind,
             "detail": self.detail}
        if with_methods:
            d["methods"] = "; ".join(self.methods)
        return d


async def check_user(cl, email, ctx: DomainCtx, pacer: Pacer) -> Result:
    """Fast existence check: GetCredentialType (one request, gives existence AND
    account type); OAuth2 is used only as a fallback when GCT is inconclusive."""
    dom = email.split("@", 1)[1]
    if not (_is_microsoft(ctx) or _is_consumer_domain(dom)):
        return Result(email, "UNKNOWN", detail="not a Microsoft identity")

    await pacer.wait()
    verdict, kind, detail, methods = await _probe_gct(cl, email, ctx)
    if verdict == "unknown":                       # fall back to the OAuth2 oracle
        await pacer.wait()
        v2, d2 = await _probe_oauth2(cl, email, ctx)
        if v2 != "unknown":
            verdict, detail = v2, d2
    if not kind:
        kind = "personal" if _is_consumer_domain(dom) else ("organizational" if ctx.tenant else "")
    status = {"exist": "VALID", "notexist": "INVALID"}.get(verdict, "UNKNOWN")
    # keep the detail column clean: only annotate the UNKNOWN cases
    return Result(email, status, detail=(detail if status == "UNKNOWN" else ""),
                  kind=kind, methods=methods)


# =========================================================================== #
# Runners
# =========================================================================== #
def _client(timeout: float, proxy: str | None, concurrency: int) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, follow_redirects=False,
                             verify=ssl.create_default_context(), proxy=proxy or None,
                             limits=httpx.Limits(max_connections=concurrency * 2))


def _split_domain(users: list[str], domain: str | None) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for u in users:
        if "@" in u:
            d, email = u.split("@", 1)[1], u
        elif domain:
            d, email = domain, f"{u}@{domain}"
        else:
            continue
        out.setdefault(d, []).append(email)
    return out


async def run_enum(users: list[str], args) -> list[Result]:
    pacer = Pacer(args.rate)
    results: list[Result] = []
    async with _client(args.timeout, args.proxy, args.concurrency) as cl:
        for domain, emails in _split_domain(users, args.domain).items():
            ctx = await build_context(cl, domain, want_mx=False, want_domains=False)
            if _is_consumer_domain(domain):
                kind, meta = "personal accounts", []
            elif ctx.tenant:
                kind, meta = "organizational tenant", [f"{ctx.realm or 'Managed'}", ctx.cloud]
            else:
                kind, meta = "no Microsoft identity", []
            head = f"\n{C.BOLD}{C.C_}{domain}{C.X}  {C.DIM}{kind}"
            if meta:
                head += "  ·  " + " · ".join(m for m in meta if m)
            print(head + C.X)
            sem = asyncio.Semaphore(args.concurrency)

            async def one(e: str, ctx=ctx) -> Result:
                async with sem:
                    r = await check_user(cl, e, ctx, pacer)
                    _print_enum(r)
                    return r
            results += await asyncio.gather(*(one(e) for e in emails))
    return results


# Upper bound on domains profiled for the trust map — large tenants (e.g.
# microsoft.com) federate thousands of domains; the full list is still available
# via --domains, which only lists them and makes no extra requests.
_FOOTPRINT_MAX = 60


async def build_footprint(cl, root: DomainCtx, concurrency: int) -> tuple[list[DomainCtx], int]:
    """Profile the tenant's domains for the trust map — bounded and concurrent.
    Returns (contexts incl. root, number of domains omitted by the cap)."""
    seen = {root.domain}
    extra: list[str] = []
    for d in root.tenant_domains:
        if d in seen or d.endswith((".onmicrosoft.com", ".onmicrosoft.us")):
            continue
        seen.add(d)
        extra.append(d)
    omitted = max(0, len(extra) - _FOOTPRINT_MAX)
    extra = extra[:_FOOTPRINT_MAX]
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(dom: str) -> DomainCtx:
        async with sem:
            return await build_context(cl, dom, want_mx=False, want_domains=False)

    profiled = await asyncio.gather(*(one(d) for d in extra))
    return [root] + list(profiled), omitted


async def run_identity(domains: list[str], args) -> list[dict]:
    """Full domain report: identity + mail + security posture, plus the tenant's
    identity footprint and federation-trust map."""
    rows: list[dict] = []
    async with _client(args.timeout, args.proxy, args.concurrency) as cl:
        for d in domains:
            ctx = await build_context(cl, d, want_mx=True, want_domains=True,
                                      want_posture=True)
            _print_identity(ctx)
            rec = asdict(ctx)
            if ctx.tenant and ctx.tenant_domains:
                fp, omitted = await build_footprint(cl, ctx, args.concurrency)
                _print_footprint(fp, omitted)
                rec["footprint"] = [asdict(c) for c in fp]
            rows.append(rec)
    return rows


# =========================================================================== #
# USERNAME FORMAT DISCOVERY  (which convention the org uses, via existence)
# =========================================================================== #
_FMT_TEMPLATES = [
    ("{first}.{last}", "first.last"),
    ("{f}{last}",      "flast"),
    ("{first}{last}",  "firstlast"),
    ("{first}_{last}", "first_last"),
    ("{f}.{last}",     "f.last"),
    ("{first}.{l}",    "first.l"),
    ("{last}{f}",      "lastf"),
    ("{last}.{first}", "last.first"),
    ("{first}",        "first"),
    ("{last}",         "last"),
    ("{f}{mi}{last}",  "fmlast"),
]


def _name_parts(name: str) -> dict | None:
    toks = [re.sub(r"[^a-z-]", "", t.lower()) for t in re.split(r"[\s,]+", name.strip())]
    toks = [t for t in toks if t]
    if len(toks) < 2:
        return None
    first, last = toks[0], toks[-1]
    return {"first": first, "last": last, "f": first[0], "l": last[0],
            "mi": toks[1][0] if len(toks) >= 3 else ""}


def _fmt_email(tmpl: str, parts: dict, domain: str) -> str:
    try:
        local = tmpl.format(**parts)
    except (KeyError, IndexError):
        return ""
    local = re.sub(r"\.\.+", ".", local).strip("._.")
    return f"{local}@{domain}" if local else ""


def _orig_name(name: str) -> tuple[str, str]:
    """Original-case (first, last) for display and the CSV, from a full name."""
    toks = [t for t in re.split(r"[\s,]+", name.strip()) if t]
    if not toks:
        return "", ""
    return (toks[0], "") if len(toks) == 1 else (toks[0], toks[-1])


def _resolve_pattern(p: str) -> str:
    """A --pattern value → a format template, or '' if unrecognised."""
    if not p:
        return ""
    if "{" in p:                                   # raw template, e.g. {first}.{last}
        return p
    return {label: tmpl for tmpl, label in _FMT_TEMPLATES}.get(p.strip().lower(), "")


def _build_addresses(tmpl: str, roster: list[str], domain: str) -> list[dict]:
    """{first, last, email} for each name, in the given template; duplicates dropped."""
    out, seen = [], set()
    for nm in roster:
        parts = _name_parts(nm)
        if not parts:
            continue
        email = _fmt_email(tmpl, parts, domain)
        if not email or email in seen:
            continue
        seen.add(email)
        first, last = _orig_name(nm)
        out.append({"first": first, "last": last, "email": email})
    return out


async def run_format(names: list[str], domain: str, args) -> dict:
    # --pattern: a known convention is supplied, so skip detection and just build
    # the address list from the provided names — no requests are made.
    if getattr(args, "pattern", None):
        tmpl = _resolve_pattern(args.pattern)
        roster = list(names) + (_lines(args.expand) if getattr(args, "expand", None) else [])
        addresses = _build_addresses(tmpl, roster, domain)
        print(f"\n{C.BOLD}{C.C_}{domain}{C.X}  {C.DIM}address list  ·  pattern "
              f"{args.pattern}  ·  {len(addresses)} generated{C.X}")
        for a in addresses:
            print(f"  {a['email']}")
        return {"domain": domain, "convention": args.pattern,
                "addresses": addresses, "ranking": {}}

    pacer = Pacer(args.rate)
    scores = {label: {"hit": 0, "miss": 0, "example": ""} for _, label in _FMT_TEMPLATES}
    async with _client(args.timeout, args.proxy, args.concurrency) as cl:
        ctx = await build_context(cl, domain, want_mx=False, want_domains=False)
        head = (f"\n{C.BOLD}{C.C_}{domain}{C.X}  {C.DIM}username-format discovery"
                f"  ·  {len(names)} known name(s){C.X}")
        print(head)
        if not _is_microsoft(ctx):
            print(f"  {C.Y}no Microsoft tenant for this domain — results may be unreliable{C.X}")
        for name in names:
            parts = _name_parts(name)
            if not parts:
                print(f"  {C.DIM}skip (need first & last): {name}{C.X}")
                continue
            found, tested = None, set()
            for tmpl, label in _FMT_TEMPLATES:
                email = _fmt_email(tmpl, parts, domain)
                if not email or email in tested:   # skip duplicates (e.g. flast == fmlast)
                    continue
                tested.add(email)
                await pacer.wait()
                verdict, _k, _d, _m = await _probe_gct(cl, email, ctx)
                if verdict == "exist":
                    scores[label]["hit"] += 1
                    scores[label]["example"] = email
                    found = (label, email)
                    break                          # convention found — stop testing this name
                if verdict == "notexist":
                    scores[label]["miss"] += 1
            if found:
                print(f"  {C.G}{name:<26}{C.X} → {C.BOLD}{found[0]}{C.X}  {C.DIM}{found[1]}{C.X}")
            else:
                print(f"  {C.Y}{name:<26}{C.X} → no format matched an existing account")
        ranked = sorted(_FMT_TEMPLATES, key=lambda t: (-scores[t[1]]["hit"], scores[t[1]]["miss"]))
        print(f"\n{C.BOLD}Format ranking{C.X}  {C.DIM}(by confirmed accounts){C.X}")
        for tmpl, label in ranked:
            s = scores[label]
            if not s["hit"] and not s["miss"]:
                continue
            mark = C.G + C.BOLD if s["hit"] else C.DIM
            print(f"  {mark}{label:<14}{C.X} hits:{s['hit']:<3} "
                  f"{C.DIM}{s['example']}{C.X}")
        best = ranked[0][1] if scores[ranked[0][1]]["hit"] else ""
        best_tmpl = next((t for t, l in _FMT_TEMPLATES if l == best), "")
        if best:
            print(f"\n{C.G}{C.BOLD}Detected convention: {best}{C.X}  "
                  f"{C.DIM}({scores[best]['hit']} confirmed){C.X}")
        # Generate an address list in the detected convention. The roster is the
        # --expand name file when given, otherwise the known names themselves, so
        # -o always yields a First/Last/Email list.
        addresses: list[dict] = []
        if best_tmpl:
            use_expand = getattr(args, "expand", None)
            roster = _lines(use_expand) if use_expand else names
            addresses = _build_addresses(best_tmpl, roster, domain)
            src = use_expand if use_expand else "the known names"
            print(f"\n{C.BOLD}Address list{C.X}  {C.DIM}({best}) — "
                  f"{len(addresses)} from {src}{C.X}")
            for a in addresses:
                print(f"  {a['email']}")
        return {"domain": domain, "convention": best, "addresses": addresses,
                "ranking": {l: scores[l] for _, l in _FMT_TEMPLATES}}


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
_SHOW_METHODS = {"on": False}


def _print_enum(r: Result) -> None:
    c = {"VALID": C.G, "INVALID": C.DIM, "UNKNOWN": C.Y}.get(r.status, C.DIM)
    tail = r.detail
    if _SHOW_METHODS["on"] and r.status == "VALID" and r.methods:
        tail = ", ".join(r.methods)
    print(f"  {c}{r.status:<8}{C.X} {r.user:<36} "
          f"{C.B}{(r.kind or '-'):<15}{C.X}{C.DIM}{tail}{C.X}")


def _print_footprint(fp: list, omitted: int = 0) -> None:
    print(f"\n  {C.BOLD}Identity footprint & federation trust{C.X}")
    # Fixed-width columns first, the variable-length domain last — so a long
    # domain extends to the right instead of shifting the whole table.
    print(f"  {C.DIM}{'REALM':<10} {'CLOUD':<24} {'TRUSTS IdP':<22} DOMAIN{C.X}")
    for c in fp:
        if c.realm == "Federated" and c.federation_url:
            idp = _idp_vendor(c.federation_url)
        elif c.tenant:
            idp = "Entra ID (managed)"
        else:
            idp = c.provider or "non-Microsoft"
        print(f"  {C.B}{(c.realm or '-'):<10}{C.X} {C.DIM}{(c.cloud or '-'):<24}{C.X} "
              f"{idp:<22} {C.C_}{c.domain}{C.X}")
    if omitted:
        print(f"  {C.DIM}… and {omitted} more domain(s) not profiled "
              f"(use --domains to export the full list){C.X}")


def _print_identity(ctx: DomainCtx) -> None:
    """Combined identity + mail + security-posture report for one domain."""
    print(f"\n{C.BOLD}{C.C_}{ctx.domain}{C.X}")

    def line(k: str, v: str, warn: bool = False) -> None:
        print(f"  {k:<18}{(C.Y if warn else C.X)}{v}{C.X}")

    line("Mailbox provider", (ctx.provider or "-")
         + (f"  ({ctx.mailbox_host})" if ctx.mailbox_host else ""))
    if not ctx.tenant:
        if ctx.provider in ("", "Unknown"):
            print(f"  {C.DIM}no Entra tenant; mailbox provider unknown{C.X}")
        return
    line("Entra cloud", ctx.cloud or "-")
    line("Authentication", (ctx.realm or "-")
         + (f"  →  {ctx.idp_vendor}" if ctx.idp_vendor else ""))
    if ctx.tenant_id:
        line("Tenant ID", ctx.tenant_id)
    if ctx.region:
        line("Region", ctx.region)
    if ctx.brand:
        line("Tenant brand", ctx.brand)
    if ctx.onmicrosoft:
        line("Default domain", ctx.onmicrosoft)
    # Posture signals — shown only when they carry a concrete answer, so the
    # report never fills up with "indeterminate" rows.
    if ctx.desktop_sso in ("enabled", "disabled"):
        line("Seamless SSO", ctx.desktop_sso, warn=(ctx.desktop_sso == "enabled"))
    if ctx.realm == "Federated" and ctx.federation_url:
        line("Federation IdP", ctx.federation_url)
        if ctx.idp_version:
            line("IdP version", ctx.idp_version)
    if ctx.legacy_auth and not ctx.legacy_auth.startswith("indeterminate"):
        line("Legacy auth", ctx.legacy_auth, warn=("reachable" in ctx.legacy_auth))
    if ctx.auth_methods:
        line("Auth methods", ", ".join(ctx.auth_methods))


def _ext(path: str) -> str:
    p = path.lower()
    return "json" if p.endswith(".json") else "csv" if p.endswith(".csv") else "txt"


def _dump_json(obj, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def _csv_safe(v) -> str:
    """Neutralise CSV formula injection: a cell derived from target data (e.g. a
    tenant's brand name) that starts with = + - @ or a control char would run as
    a formula in Excel/Sheets, so prefix it with a quote."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _dump_csv(rows: list[dict], fields: list[str], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _csv_safe(r.get(k, "")) for k in fields})


def _dump_txt(lines: list[str], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def _write_enum(res: list[Result], path: str) -> None:
    rows = [r.row(with_methods=_SHOW_METHODS["on"]) for r in res]
    fields = ["user", "status", "kind", "detail"] + (["methods"] if _SHOW_METHODS["on"] else [])
    kind = _ext(path)
    if kind == "json":
        _dump_json(rows, path)
    elif kind == "csv":
        _dump_csv(rows, fields, path)
    else:                                   # txt: existing accounts only, one per line
        _dump_txt([r.user for r in res if r.status == "VALID"], path)


# Columns used for the identity CSV / flat view.
_ID_FIELDS = ["domain", "tenant", "cloud", "realm", "tenant_id", "region", "brand",
              "onmicrosoft", "idp_vendor", "idp_version", "desktop_sso", "legacy_auth",
              "auth_methods", "provider", "mailbox_host", "tenant_domains"]


def _id_flat(rec: dict) -> dict:
    flat = {k: rec.get(k, "") for k in _ID_FIELDS}
    flat["auth_methods"] = "; ".join(rec.get("auth_methods") or [])
    flat["tenant_domains"] = "; ".join(rec.get("tenant_domains") or [])
    return flat


def _write_identity(rows: list[dict], path: str) -> None:
    kind = _ext(path)
    if kind == "json":
        _dump_json(rows, path)
    elif kind == "csv":
        _dump_csv([_id_flat(r) for r in rows], _ID_FIELDS, path)
    else:                                   # txt: key: value blocks per domain
        lines: list[str] = []
        for r in rows:
            lines.append(f"# {r.get('domain', '')}")
            for k, v in _id_flat(r).items():
                if v != "" and v is not False:
                    lines.append(f"{k}: {v}")
            lines.append("")
        _dump_txt(lines, path)


def _write_format(rec: dict, path: str) -> None:
    addresses = rec.get("addresses", [])
    kind = _ext(path)
    if kind == "json":
        _dump_json(rec, path)
    elif kind == "csv":                     # First Name,Last Name,Email
        rows = [{"First Name": a["first"], "Last Name": a["last"], "Email": a["email"]}
                for a in addresses]
        _dump_csv(rows, ["First Name", "Last Name", "Email"], path)
    else:                                   # txt: one email address per line
        _dump_txt([a["email"] for a in addresses], path)


def _write_domains(domains: list[str], path: str) -> None:
    kind = _ext(path)
    if kind == "json":
        _dump_json(domains, path)
    elif kind == "csv":
        _dump_csv([{"Domain": d} for d in domains], ["Domain"], path)
    else:                                   # txt: one domain per line
        _dump_txt(domains, path)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _lines(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [ln.split("#", 1)[0].strip() for ln in f if ln.split("#", 1)[0].strip()]


def _collect_users(args, ap) -> list[str]:
    users = list(getattr(args, "user", []) or [])
    if getattr(args, "user_file", None):
        users += _lines(args.user_file)
    users = [u.strip().lower() for u in users if u.strip()]
    return list(dict.fromkeys(users))


_ART = [
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠤⠒⠋⠉⠉⠉⠉⠑⠠⢄",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡊m365hunt⠈⡆",
    "⠀⠀⠀⢀⣰⣿⣿⣿⣿⣷⣆⠀⠀⠀⠑⢆⠀⠀⠀⠀⠀⡸⠀⠀",
    "⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⣰⠏⠑⠂⠂⠒⠂⠀⠀⠀",
    "⠀⠀⣿⣿⣿⣿⣿⠿⢿⣛⣫⣭⣶⡶⠶⠤⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⢛⣻⣭⣽⡶⢞⣛⣯⣭⣷⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⢀⠴⠟⣫⠅⣤⣥⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠘⢷⣝⢻⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⣶⣬⣜⠻⠿⣿⠿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⣰⣿⣿⣿⣿⣷⣶⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠈⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀",
]


def _banner() -> None:
    print()
    for line in _ART:
        print(f"{C.C_}{line}{C.X}")
    print(f"\n   {C.BOLD}m365hunt{C.X}  {C.DIM}Microsoft 365 / Entra identity "
          f"reconnaissance & tenant posture{C.X}")
    print(f"   {C.B}author: {C.X}{C.BOLD}black3dm0nd{C.X}")
    print(f"   {C.B}website:{C.X} {C.BOLD}https://black3dm0nd.com{C.X}")
    print(f"   {C.B}github: {C.X}{C.BOLD}https://github.com/black3dm0nd{C.X}\n")


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="m365hunt",
        description="External identity reconnaissance for Microsoft 365 and Entra ID. "
                    "Confirms which accounts exist and whether they are personal or "
                    "organizational, reports a domain's identity, mail and tenant security "
                    "posture, and infers the organisation's username convention — entirely "
                    "from public authentication endpoints, with sovereign-cloud "
                    "(Commercial / US Gov / China) support. No password is ever transmitted.")
    sub = ap.add_subparsers(dest="mode", metavar="{enum,identity,format}")

    def common(p):
        p.add_argument("-d", "--domain", metavar="DOMAIN",
                       help="Domain applied to bare usernames (e.g. -d example.com).")
        p.add_argument("-u", "--user", action="append", default=[], metavar="USER",
                       help="Username or email address; repeatable.")
        p.add_argument("-U", "--user-file", metavar="FILE",
                       help="File of usernames or email addresses, one per line.")
        p.add_argument("-o", "--output", metavar="FILE",
                       help="Write results to a file; format inferred from the extension "
                            "(.json, .csv, .txt).")
        p.add_argument("-c", "--concurrency", type=int, default=5, metavar="N",
                       help="Maximum concurrent requests (default: 5).")
        p.add_argument("--rate", type=float, default=1.0, metavar="N",
                       help="Maximum requests per second, jittered (default: 1.0).")
        p.add_argument("--timeout", type=float, default=20.0, metavar="SECONDS",
                       help="Per-request timeout in seconds (default: 20).")
        p.add_argument("--proxy", metavar="URL",
                       help="Route all traffic through an HTTP or SOCKS proxy.")
        p.add_argument("--timestamp", action="store_true",
                       help="Print the start time before the run.")
        p.add_argument("--debug", action="store_true",
                       help="Print raw endpoint responses for troubleshooting.")

    def netargs(p):
        p.add_argument("-o", "--output", metavar="FILE",
                       help="Write the report to a file; format inferred from the "
                            "extension (.json, .csv, .txt).")
        p.add_argument("-c", "--concurrency", type=int, default=5, metavar="N",
                       help="Maximum concurrent requests (default: 5).")
        p.add_argument("--rate", type=float, default=1.0, metavar="N",
                       help="Maximum requests per second, jittered (default: 1.0).")
        p.add_argument("--timeout", type=float, default=20.0, metavar="SECONDS",
                       help="Per-request timeout in seconds (default: 20).")
        p.add_argument("--proxy", metavar="URL",
                       help="Route all traffic through an HTTP or SOCKS proxy.")
        p.add_argument("--timestamp", action="store_true",
                       help="Print the start time before the run.")
        p.add_argument("--debug", action="store_true",
                       help="Print raw endpoint responses for troubleshooting.")

    pe = sub.add_parser("enum",
                        help="Confirm which accounts exist and classify each as "
                             "personal or organizational.",
                        description="Confirm which Microsoft 365 / Entra accounts exist and "
                                    "classify each as personal (consumer MSA) or organizational "
                                    "(Entra tenant). Identities are given as full emails, or as "
                                    "bare usernames with -d, via -u (repeatable) or -U (a file); "
                                    "each is checked with a single existence probe, so the pass "
                                    "stays fast. --methods additionally infers the advertised "
                                    "sign-in methods. Accounts on non-Microsoft domains are "
                                    "reported UNKNOWN, never guessed.")
    common(pe)
    pe.add_argument("--methods", action="store_true",
                    help="Infer each valid account's advertised sign-in methods "
                         "(password, Authenticator, FIDO2, SMS, federation).")

    pi = sub.add_parser("identity",
                        help="Report a domain's identity, mail and tenant security posture.",
                        description="Report everything configured for a domain from public "
                                    "endpoints only: mail provider, sovereign cloud, Entra "
                                    "tenant and region, Managed vs Federated, the federation "
                                    "IdP and ADFS version, Seamless SSO, legacy-auth "
                                    "reachability, and advertised sign-in methods, then map the "
                                    "whole tenant's identity footprint and federation trust. "
                                    "Posture signals are shown only when they resolve to a "
                                    "concrete answer.")
    pi.add_argument("domain", nargs="+", metavar="DOMAIN",
                    help="One or more domains to profile.")
    pi.add_argument("--domains", metavar="FILE",
                    help="Write the tenant's domain list to FILE (.txt / .csv / .json), "
                         "ready to feed into `enum`.")
    netargs(pi)

    pf = sub.add_parser("format",
                        help="Detect the org's username convention, or apply a given one, "
                             "and build an email-address list from names.",
                        description="Build an email-address list for an organisation. By "
                                    "default the convention (first.last, flast, …) is detected "
                                    "by testing candidate addresses for a few known people "
                                    "against GetCredentialType; with --pattern a convention you "
                                    "already know is applied and no requests are made. The list "
                                    "is generated from the given names (-n / -N and/or --expand) "
                                    "and is ready for username enumeration. Save it with -o "
                                    "(.txt = emails, .csv = First Name,Last Name,Email, .json = full).")
    pf.add_argument("-d", "--domain", required=True, metavar="DOMAIN",
                    help="Target domain for the generated addresses.")
    pf.add_argument("-n", "--name", action="append", default=[], metavar='"First Last"',
                    help="A full name; repeatable. Used to detect the convention, and as "
                         "generation input.")
    pf.add_argument("-N", "--name-file", metavar="FILE",
                    help="File of full names, one per line.")
    pf.add_argument("--pattern", metavar="FMT",
                    help="Apply this known username format instead of detecting it: a label "
                         "(first.last, flast, firstlast, first_last, f.last, lastf, last.first) "
                         "or a template such as '{first}.{last}'. Skips all probing.")
    pf.add_argument("--expand", metavar="FILE",
                    help="Additional file of names to include in the generated address list.")
    netargs(pf)

    args = ap.parse_args()
    _DBG["on"] = getattr(args, "debug", False)
    _SHOW_METHODS["on"] = getattr(args, "methods", False)
    _banner()
    if not args.mode:                       # bare `./m365hunt.py` -> banner + help
        ap.print_help()
        return
    if getattr(args, "timestamp", False):
        print(f"   {C.DIM}started {time.strftime('%Y-%m-%d %H:%M:%S %Z')}{C.X}\n")

    if args.mode == "identity":
        rows = asyncio.run(run_identity([d.strip().lower() for d in args.domain], args))
        if args.domains:
            alld: list[str] = []
            for r in rows:
                alld += r.get("tenant_domains") or []
            alld = list(dict.fromkeys(alld))
            _write_domains(alld, args.domains)
            print(f"\n{C.G}wrote {len(alld)} tenant domain(s) to {args.domains}{C.X}")
        if args.output:
            _write_identity(rows, args.output)
            print(f"\n{C.G}wrote {args.output}{C.X}")
        return

    if args.mode == "format":
        names = list(args.name)
        if args.name_file:
            names += _lines(args.name_file)
        names = [n.strip() for n in names if n.strip()]
        if args.pattern:
            if not _resolve_pattern(args.pattern):
                ap.error(f"unknown --pattern '{args.pattern}'; use a label "
                         f"({', '.join(l for _, l in _FMT_TEMPLATES)}) or a "
                         f"'{{first}}.{{last}}' template")
            if not names and not args.expand:
                ap.error("no names to generate from (use -n / -N or --expand FILE)")
        elif not names:
            ap.error("no names given to detect the convention (use -n / -N)")
        rec = asyncio.run(run_format(names, args.domain.strip().lower(), args))
        if args.output:
            _write_format(rec, args.output)
            print(f"\n{C.G}wrote {args.output}{C.X}")
        return

    users = _collect_users(args, ap)
    if not users:
        ap.error("no users given (use -u / -U)")

    res = asyncio.run(run_enum(users, args))
    _summary(res)
    valid = [r for r in res if r.status == "VALID"]
    if valid:
        print(f"\n{C.G}{C.BOLD}Valid accounts{C.X}")
        for r in valid:
            extra = f"   {C.DIM}{', '.join(r.methods)}{C.X}" if (_SHOW_METHODS["on"] and r.methods) else ""
            print(f"  {C.G}{r.user}{C.X}{extra}")
    if args.output:
        _write_enum(res, args.output)
        print(f"\n{C.G}wrote {args.output}{C.X}")


def _summary(res: list[Result]) -> None:
    counts: dict[str, int] = {}
    for r in res:
        counts[r.status] = counts.get(r.status, 0) + 1
    parts = "   ".join(f"{k.title()}: {v}" for k, v in sorted(counts.items()))
    print(f"\n{C.BOLD}Summary{C.X}   {parts}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
