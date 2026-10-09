# m365hunt

> External identity reconnaissance for Microsoft 365 and Entra ID — account
> enumeration, domain identity & tenant security posture, and username-convention
> discovery, from public authentication endpoints. No password is ever transmitted.

`m365hunt` has three credential-free operations:

- **enum** — does a Microsoft 365 / Entra account exist, and is it a **personal**
  (consumer MSA) or an **organizational** (Entra tenant) account? Existence only.
  With `--methods`, also infer each valid account's advertised sign-in methods
  (password, Authenticator, FIDO2, SMS, federation).
- **identity** — the full picture of a domain: mailbox provider, sovereign cloud,
  Entra tenant GUID and region, Managed vs Federated, the **federation IdP** and
  **ADFS version**, **Seamless SSO**, **legacy-auth reachability**, and advertised
  sign-in methods — plus the tenant's whole **identity footprint & federation-trust
  map**. `--domains FILE` extracts the tenant's domain list.
- **format** — infer the organisation's **username convention** (`first.last`,
  `flast`, …) from a few known names and build an email-address list ready for
  enumeration — or apply a convention you already know with `--pattern`.

**Author:** black3dm0nd · [black3dm0nd.com](https://black3dm0nd.com) ·
[github.com/black3dm0nd](https://github.com/black3dm0nd)

---

## How enumeration works

`m365hunt` resolves each domain once, then checks each user with a single fast
request — escalating only when it has to:

1. **Tenant fingerprint (once per domain).** The **sovereign cloud** (Commercial,
   US Gov `login.microsoftonline.us`, or China) and Managed vs Federated realm are
   resolved via `getuserrealm` — the authoritative cloud oracle — so every probe
   hits the right cloud. Probes also **fall back across clouds** when the primary
   says the user/tenant is not there, so a GCC High / DoD account is validated on
   `.us` rather than mis-reported as invalid on `.com`.
2. **One request per user.** `GetCredentialType` returns existence **and** account
   type in a single call. Only when it is inconclusive does the tool fall back to
   the OAuth2 oracle — so enumeration stays fast.
3. **Personal vs organizational.** Every hit is labelled `personal` (consumer MSA),
   `organizational` (Entra tenant), or `both`. Non-Microsoft domains are reported
   as such, not guessed.

| Status | Meaning |
|--------|---------|
| `VALID` | account exists (labelled personal / organizational / both) |
| `INVALID` | account does not exist |
| `UNKNOWN` | no definitive answer, or the domain is non-Microsoft |

---

## Identity & posture (`identity`)

One pass over public endpoints returns everything configured for a domain:

| Signal | Source |
|--------|--------|
| **Mailbox provider** | MX (via DoH) |
| **Sovereign cloud** / **Managed vs Federated** | `getuserrealm` |
| **Tenant GUID** / **region** | OpenID configuration |
| **Seamless SSO** (Desktop SSO) | `GetCredentialType` → `EstsProperties.DesktopSsoEnabled` |
| **Federation IdP** (Okta / Ping / AD FS / Entra …) | realm `AuthURL` fingerprint |
| **AD FS version** | the IdP sign-in page |
| **Legacy auth reachable** | WS-Trust `usernamemixed` endpoint probe (federated) |
| **Advertised sign-in methods** | `GetCredentialType` `Credentials` block |

An Entra tenant always has Exchange Online, so it is reported as **Microsoft 365**
even when inbound mail is routed through an unrecognised gateway — a real M365 org
is never mislabelled "Self-hosted". Posture signals are shown **only when they
resolve to a concrete answer**; anything that would be `indeterminate` (e.g. SSPR
and conditional access, which need an authenticated session) is omitted.

The report ends with the tenant's **identity footprint & federation-trust map** —
every domain in the tenant with its realm, cloud, and the IdP it trusts (fixed-width
columns first, so a long domain never shifts the table). Use `--domains FILE` to
write that domain list (`.txt` / `.csv` / `.json`) straight into the next `enum`.

---

## Username format & address lists (`format`)

Builds an **email-address list** for an organisation, ready for username
enumeration. Two modes:

- **Detect** (default) — give a few **known names** (`-n` / `-N`); it tries each
  common convention (`first.last`, `flast`, `firstlast`, `first_last`, …) against
  `GetCredentialType` and keeps the one that holds across the known people.
- **Apply** (`--pattern`) — you already know the convention, so pass it (a label
  like `flast`, or a template like `{first}.{last}`) and **no requests are made**;
  it just generates the addresses.

The list is generated from the given names (`-n` / `-N` and/or `--expand FILE`) and
saved with `-o`:

- `.txt` — one email address per line
- `.csv` — `First Name,Last Name,Email`
- `.json` — convention + full address list (+ the format ranking, in detect mode)

---

## Install

Requires **Python 3.10+** and a single dependency (`httpx`).

```bash
git clone https://github.com/black3dm0nd/m365hunt
cd m365hunt
python3 -m pip install -r requirements.txt
```

Optional: `pip install "httpx[socks]"` to route through a SOCKS `--proxy`.

---

## Usage

```bash
# No arguments → banner + help
./m365hunt.py

# Enumeration: one user, or a list (domain applied to bare names)
./m365hunt.py enum -d acme.com -u jdoe -u asmith
./m365hunt.py enum -U emails.txt
./m365hunt.py enum -d acme.com -U users.txt -o valid.txt        # VALID users, one per line
./m365hunt.py enum -U emails.txt -o results.csv --rate 0.5       # full detail + pacing
./m365hunt.py enum -d acme.com -U users.txt --methods           # + advertised sign-in methods

# Identity, tenant posture, and federation-trust footprint
./m365hunt.py identity acme.com
./m365hunt.py identity acme.com -o report.json
./m365hunt.py identity acme.com --domains tenant-domains.txt    # extract the tenant domains

# Address lists for username enumeration
./m365hunt.py format -d acme.com -n "Jane Doe" -n "Alan Smith"               # detect convention
./m365hunt.py format -d acme.com -N known.txt --expand roster.txt -o people.csv
./m365hunt.py format -d acme.com --pattern flast -N staff.txt -o emails.txt  # apply a known format

# Through a proxy
./m365hunt.py enum -U emails.txt --proxy socks5://127.0.0.1:9050
```

### Options

| Flag | Purpose |
|------|---------|
| `-d, --domain` | domain to apply when users/names are bare |
| `-u, --user` / `-U, --user-file` | *(enum)* identities (repeatable / one per line, `#` comments ok) |
| `-n, --name` / `-N, --name-file` | *(format)* full names (repeatable / one per line) |
| `--methods` | *(enum)* infer each valid account's advertised sign-in methods |
| `--domains FILE` | *(identity)* write the tenant's domain list to FILE |
| `--pattern FMT` | *(format)* apply a known convention instead of detecting it |
| `--expand FILE` | *(format)* extra names to include in the generated list |
| `-o, --output` | write results — `.txt` / `.csv` / `.json`, by extension |
| `-c, --concurrency` | parallel requests (default 5) |
| `--rate` | max requests/second, jittered (default 1.0) |
| `--timeout` | per-request timeout, seconds (default 20) |
| `--proxy` | HTTP/SOCKS proxy for all traffic |
| `--timestamp` | print the start time before the run |
| `--debug` | print the raw HTTP status / AADSTS code / response body per attempt |

Output per module (format chosen by the `-o` extension):

| Module | `.txt` | `.csv` | `.json` |
|--------|--------|--------|---------|
| `enum` | VALID users, one per line | `user,status,kind,detail[,methods]` | full results |
| `identity` | `key: value` block per domain | one flat row per domain | full report (+ footprint) |
| `format` | one email per line | `First Name,Last Name,Email` | convention + addresses (+ ranking) |

---

## Data sources

No API keys are required.

| Endpoint | Used for |
|----------|----------|
| `login.microsoftonline.com` / `.us` / `.partner.microsoftonline.cn` | realm, GetCredentialType, OpenID config, OAuth2 |
| `autodiscover-s.outlook.com` / `.office365.us` / `.partner.outlook.cn` | tenant-domain enumeration |
| the tenant's ADFS / federation IdP | IdP fingerprint, AD FS version, legacy-auth reachability |
| Cloudflare DoH (`cloudflare-dns.com`) | MX lookup for the mailbox provider |

---

## Design

- **No credential is ever sent to a target.** Existence probes submit a random
  throwaway value; only metadata and authentication-flow signals are read.
- **TLS verification stays on** for every request (`ssl.create_default_context`).
- No `eval` / `exec`, no shell-outs; all I/O goes through `httpx`.
- Async throughout — rate-limited, concurrency-capped, and `--proxy`-aware.

---

## Legal

m365hunt is for security professionals operating within a defined engagement —
penetration tests and red-team operations against identities and tenants you own or
are contracted to assess. Its probes are active techniques that query the target's
identity providers.

Responsibility for operating within an authorized scope and in accordance with
applicable law rests entirely with the operator. The author accepts no liability for
misuse or for any damage arising from use of this tool.

---

## Project layout

```
m365hunt/
├── m365hunt.py        # the tool (enum · identity · format)
├── README.md
├── requirements.txt   # httpx
├── LICENSE            # MIT
└── .gitignore
```

## License

MIT © black3dm0nd
