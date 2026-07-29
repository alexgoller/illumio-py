# illumio-py-open examples

Runnable example scripts for the `illumio` client. Each is a small, standalone
program you can read top-to-bottom and run against a PCE.

## Setup

```sh
pip install illumio-py-open
```

Provide connection details via environment variables or a `.env` file in the
directory you run from (copy `.env.example`):

```
PCE_HOST=my.pce.com
PCE_PORT=443
PCE_ORG_ID=1
API_KEY=api_xxxxxxxx
API_SECRET=xxxxxxxx
```

Run an example **from inside this `examples/` directory** (they share
`_common.py` for the connection):

```sh
cd examples
python 01_connect.py
```

## The examples

| Script | What it shows | Writes? |
|---|---|---|
| `01_connect.py` | Connect and read basic facts | read-only |
| `02_labels.py` | Labels CRUD + label groups | creates/deletes labels |
| `03_ip_lists_and_services.py` | IP lists and services (rule building blocks) | creates/deletes drafts |
| `04_workloads.py` | Query workloads; create an unmanaged workload; enforcement mode | creates/deletes one workload |
| `05_allow_rules.py` | Build an allow policy: labels → ruleset → rule | creates/deletes drafts |
| `06_deny_rules.py` | Deny and override-deny rules (single `deny_rules` endpoint) | creates/deletes drafts |
| `07_traffic_analysis.py` | Explorer async traffic query | read-only |
| `08_provisioning.py` | draft → active provisioning workflow | creates + provisions |
| `09_vens.py` | Inspect VENs, statistics, software releases | read-only |
| `10_bulk_operations.py` | Bulk create/delete workloads | creates/deletes drafts |
| `11_settings_and_reporting.py` | Org settings, password policy, reports | read-only |
| `12_pairing_profiles.py` | Pairing profile + pairing key for VEN onboarding | creates/deletes a profile |
| `13_onboard_unmanaged_workloads.py` | **Bulk-onboard unmanaged workloads + labels the rate-limit-safe way** (prefetch label map → get-or-create → `bulk_create`) | creates/deletes drafts |
| `14_async_rate_limited_sync.py` | **Async onboarding that stays under the rate limit** (`gather` + `Semaphore` + token-ish limiter + `to_thread`) | creates/deletes |

## Notes

- **Write examples create clearly-named `Example`/`IPL-Example` objects and clean
  up after themselves.** Security-policy objects are created in *draft* and are
  not enforced until provisioned (see `08_provisioning.py`).
- **Direction:** in Illumio rules, *consumers* are the sources that initiate
  connections to *providers* (the destinations).
- Treat pairing keys and API secrets as secrets — do not log or commit them.
