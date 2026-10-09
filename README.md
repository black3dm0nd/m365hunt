# m365hunt

```text
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠤⠒⠋⠉⠉⠉⠉⠑⠠⢄        ╔════════════════════════════════════════════╗
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡊m365hunt⠈⡆                     m365hunt
⠀⠀⠀⢀⣰⣿⣿⣿⣿⣷⣆⠀⠀⠀⠑⢆⠀⠀⠀⠀⠀⡸⠀⠀        ║ Microsoft 365 / Entra ID recon             ║
⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⣰⠏⠑⠂⠂⠒⠂⠀⠀⠀        ╠════════════════════════════════════════════╣
⠀⠀⣿⣿⣿⣿⣿⠿⢿⣛⣫⣭⣶⡶⠶⠤⠀⠀⠀⠀⠀⠀⠀⠀        ║ modules  enum | identity | format          ║
⠀⠀⢛⣻⣭⣽⡶⢞⣛⣯⣭⣷⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        ║ author   black3dm0nd                      ║
⢀⠴⠟⣫⠅⣤⣥⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        ║ website  black3dm0nd.com                  ║
⠀⠀⠀⠘⢷⣝⢻⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        ║ github   github.com/black3dm0nd           ║
⠀⠀⠀⠀⣶⣬⣜⠻⠿⣿⠿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀        ╚════════════════════════════════════════════╝
⠀⠀⠀⣰⣿⣿⣿⣿⣷⣶⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠈⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀
```

External identity reconnaissance for Microsoft 365 and Entra ID. `m365hunt`
performs account enumeration, domain identity and tenant posture discovery, and
username-format detection from public authentication endpoints.

No real password is ever transmitted. Existence probes use a random throwaway
value and read only metadata and authentication-flow signals.

## Features

`m365hunt` provides three credential-free modules:

| Module | Purpose |
| --- | --- |
| `enum` | Check whether Microsoft 365 / Entra accounts exist and classify them as personal, organizational, or both. |
| `identity` | Profile a domain's Microsoft 365 / Entra identity posture, mail provider, federation state, tenant metadata, and trust footprint. |
| `format` | Detect or apply an organization's username convention and generate email-address lists for enumeration. |

Key capabilities:

- Microsoft 365 / Entra account existence checks.
- Personal Microsoft account vs organizational Entra account classification.
- Sovereign cloud support for Commercial, US Gov, and China tenants.
- Managed vs Federated realm discovery.
- Federation IdP and AD FS version fingerprinting where available.
- Seamless SSO and legacy-auth reachability signals where public endpoints expose them.
- Tenant domain footprint extraction.
- Username convention detection from known names.
- TXT, CSV, and JSON output support.
- Async requests with concurrency, pacing, timeout, proxy, and debug controls.

---

## Project Structure

```text
m365hunt/
├── m365hunt.py        # single-file CLI tool: enum, identity, and format modules
├── README.md          # project documentation
├── requirements.txt   # Python dependency list
├── LICENSE            # MIT license
├── .gitignore
└── .gitattributes
```

The project is intentionally compact. The core logic, CLI parser, output writers,
banner, and public-endpoint probes all live in `m365hunt.py`. The only runtime
dependency listed in `requirements.txt` is `httpx`.

---

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/black3dm0nd/m365hunt
cd m365hunt
python3 -m pip install -r requirements.txt
```

Optional SOCKS proxy support:

```bash
python3 -m pip install "httpx[socks]"
```

---

## Quick Start

Run the tool with no arguments to show the banner and help:

```bash
./m365hunt.py
```

Enumerate one or more users:

```bash
./m365hunt.py enum -d acme.com -u jdoe -u asmith
./m365hunt.py enum -U emails.txt
./m365hunt.py enum -d acme.com -U users.txt --methods
```

Profile a domain's identity posture:

```bash
./m365hunt.py identity acme.com
./m365hunt.py identity acme.com -o report.json
./m365hunt.py identity acme.com --domains tenant-domains.txt
```

Detect or apply a username convention:

```bash
./m365hunt.py format -d acme.com -n "Jane Doe" -n "Alan Smith"
./m365hunt.py format -d acme.com -N known.txt --expand roster.txt -o people.csv
./m365hunt.py format -d acme.com --pattern flast -N staff.txt -o emails.txt
```

Route traffic through a proxy:

```bash
./m365hunt.py enum -U emails.txt --proxy socks5://127.0.0.1:9050
```

---

## Module Details

### `enum`

Checks whether identities exist in Microsoft 365 / Entra ID and classifies valid
hits as `personal`, `organizational`, or `both`.

Enumeration flow:

1. Resolve the domain's tenant realm and sovereign cloud once.
2. Probe each user with `GetCredentialType`.
3. Fall back to the OAuth2 oracle only when the primary probe is inconclusive.
4. Report non-Microsoft domains as `UNKNOWN` instead of guessing.

Status values:

| Status | Meaning |
| --- | --- |
| `VALID` | Account exists. |
| `INVALID` | Account does not exist. |
| `UNKNOWN` | No definitive answer, or the domain is not Microsoft-backed. |

With `--methods`, valid accounts also include advertised sign-in methods such as
password, Authenticator, FIDO2 / passkey, SMS / voice OTP, certificate auth, or
federated IdP redirect when those signals are exposed.

### `identity`

Profiles a domain from public endpoints and reports the identity, mail, tenant,
and federation posture signals that can be determined without credentials.

| Signal | Source |
| --- | --- |
| Mailbox provider | MX lookup through Cloudflare DoH |
| Sovereign cloud | Microsoft `getuserrealm` |
| Managed vs Federated realm | Microsoft `getuserrealm` |
| Tenant GUID and region | OpenID configuration |
| Tenant domain footprint | Autodiscover federation information |
| Seamless SSO | `GetCredentialType` `EstsProperties.DesktopSsoEnabled` |
| Federation IdP | Realm `AuthURL` fingerprint |
| AD FS version | IdP sign-in page when detectable |
| Legacy-auth reachability | WS-Trust `usernamemixed` endpoint probe |
| Advertised sign-in methods | `GetCredentialType` `Credentials` block |

The report ends with the tenant's identity footprint and federation-trust map.
Use `--domains FILE` to export discovered tenant domains to `.txt`, `.csv`, or
`.json` for reuse with `enum`.

### `format`

Builds an email-address list for an organization.

Two modes are available:

| Mode | Description |
| --- | --- |
| Detect | Provide known names with `-n` or `-N`; the tool tests common conventions and ranks the matches. |
| Apply | Provide `--pattern`; the tool generates addresses without making network requests. |

Supported pattern labels include:

- `first.last`
- `flast`
- `firstlast`
- `first_last`
- `f.last`
- `lastf`
- `last.first`

Custom templates such as `{first}.{last}` are also accepted.

---

## CLI Options

Common network and output options:

| Flag | Purpose |
| --- | --- |
| `-o, --output FILE` | Write results to `.txt`, `.csv`, or `.json`. |
| `-c, --concurrency N` | Maximum concurrent requests. Default: `5`. |
| `--rate N` | Maximum requests per second, with jitter. Default: `1.0`. |
| `--timeout SECONDS` | Per-request timeout. Default: `20`. |
| `--proxy URL` | Route all traffic through an HTTP or SOCKS proxy. |
| `--timestamp` | Print the run start time. |
| `--debug` | Print raw HTTP status, AADSTS code, and response body per attempt. |

Module-specific options:

| Flag | Module | Purpose |
| --- | --- | --- |
| `-d, --domain DOMAIN` | `enum`, `format` | Domain applied to bare usernames or generated addresses. |
| `-u, --user USER` | `enum` | Username or email address. Repeatable. |
| `-U, --user-file FILE` | `enum` | File of usernames or email addresses. |
| `--methods` | `enum` | Infer advertised sign-in methods for valid accounts. |
| `--domains FILE` | `identity` | Export discovered tenant domains. |
| `-n, --name "First Last"` | `format` | Full name. Repeatable. |
| `-N, --name-file FILE` | `format` | File of full names. |
| `--pattern FMT` | `format` | Apply a known username convention instead of detecting one. |
| `--expand FILE` | `format` | Extra names to include in the generated address list. |

---

## Output Formats

The output format is selected from the `-o` file extension.

| Module | `.txt` | `.csv` | `.json` |
| --- | --- | --- | --- |
| `enum` | Valid users, one per line | `user,status,kind,detail[,methods]` | Full result objects |
| `identity` | `key: value` blocks per domain | One flat row per domain | Full reports with footprint data |
| `format` | One email address per line | `First Name,Last Name,Email` | Convention, addresses, and ranking |

---

## Data Sources

No API keys are required.

| Endpoint | Used for |
| --- | --- |
| `login.microsoftonline.com` | Commercial realm, `GetCredentialType`, OpenID configuration, OAuth2 |
| `login.microsoftonline.us` | US Gov realm, `GetCredentialType`, OpenID configuration, OAuth2 |
| `login.partner.microsoftonline.cn` | China realm, `GetCredentialType`, OpenID configuration, OAuth2 |
| `autodiscover-s.outlook.com` | Commercial tenant-domain enumeration |
| `autodiscover-s.office365.us` | US Gov tenant-domain enumeration |
| `autodiscover-s.partner.outlook.cn` | China tenant-domain enumeration |
| Tenant AD FS / federation IdP | IdP fingerprinting, AD FS version detection, legacy-auth reachability |
| `cloudflare-dns.com` | MX lookup through DNS over HTTPS |

---

## Design Notes

- The tool never sends a real password to a target.
- TLS verification remains enabled for every request.
- The code does not use `eval`, `exec`, or shell-outs.
- Network I/O is performed through `httpx`.
- Requests are asynchronous, concurrency-capped, rate-limited, and proxy-aware.
- CSV output neutralizes formula-injection prefixes in target-derived cells.

---

## Legal

`m365hunt` is intended for security professionals operating within a defined and
authorized scope, including penetration tests and red-team operations against
identities and tenants they own or are contracted to assess.

The tool performs active probes against target identity providers. The operator is
responsible for complying with applicable law, rules of engagement, and local
authorization requirements. The author accepts no liability for misuse or damage
arising from use of this tool.

---

## License

MIT © black3dm0nd
