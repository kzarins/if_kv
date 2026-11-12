# if_kv

Python scripts that audit which Azure Service Principals can access which Azure Key Vaults. `all_kvs.py` and `kv_sp.py` use the Azure CLI (`az`) to read your tenant; `kv_secret.py` signs in to one vault as a Service Principal. None of the scripts change anything in Azure.

| Script | Use it to |
| --- | --- |
| `all_kvs.py` | Check a list of Service Principals against every Key Vault in every enabled subscription you can see, and write a CSV and a JSON report. |
| `kv_sp.py` | List one Service Principal's Azure RBAC role assignments in the subscriptions whose names match a filter, and see which Key Vaults each assignment covers. |
| `kv_secret.py` | Sign in as a Service Principal and print the secrets it can read in one Key Vault. |

## Requirements

- Python 3.9 or newer. Only the standard library is used, so there is nothing to `pip install`.
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli), with `az` on your `PATH`.
- An Azure identity that can read:
  - subscriptions, Key Vaults, and Key Vault properties (`Reader` is enough);
  - role assignments and role definitions;
  - Service Principals in Microsoft Entra ID (`az ad sp show`).

Sign in before you run either script:

```bash
az login
```

If a subscription or vault can't be read, the scripts print a warning and keep going. `all_kvs.py` also lists these failures under `scanErrors` in its JSON report.

## all_kvs.py: scan every Key Vault

Create a text file with one Service Principal **client ID** (application ID) on each line. Blank lines and anything after `#` are ignored, and duplicates are skipped.

```text
# ids.txt
11111111-2222-3333-4444-555555555555
66666666-7777-8888-9999-000000000000   # build pipeline
```

Run:

```bash
python3 all_kvs.py --client-ids-file ids.txt
```

| Option | Default | Description |
| --- | --- | --- |
| `--client-ids-file` | required | The file of client IDs. |
| `--csv-report` | `sp_keyvault_access_report.csv` | Where to write the CSV report. |
| `--json-report` | `sp_keyvault_access_report.json` | Where to write the JSON report. |

For each vault, the script checks the authorization model the vault uses:

- **Azure RBAC vaults**: role assignments on the vault itself (`direct-vault`), on a parent scope such as a resource group or subscription (`inherited-parent`), or on a single secret, key or certificate (`child-resource-only`). The role's data actions are converted into capabilities such as `Secrets: Get` or `Keys: Decrypt`. Roles that grant no Key Vault data access, such as `Reader`, are left out.
- **Access-policy vaults**: access policies that name the Service Principal directly.

Progress is printed as the scan runs. Each report has one row per Service Principal, vault and grant. The JSON report also lists the resolved Service Principals, any client IDs that couldn't be resolved, and scan errors.

## kv_sp.py: one Service Principal's role assignments

```bash
python3 kv_sp.py --client-id 11111111-2222-3333-4444-555555555555 --subscription-filter prod
```

| Option | Default | Description |
| --- | --- | --- |
| `--client-id` | required | The Service Principal's client ID (application ID). |
| `--subscription-filter` | required | Text that must appear in the subscription name. The match ignores case. |
| `--json-file` | none | Also save the full result as JSON at this path. |

For every enabled subscription whose name contains the filter, the script prints each role assignment the Service Principal has there. It also lists the Key Vaults each assignment covers, with the same `direct-vault`, `inherited-parent` and `child-resource-only` labels.

## kv_secret.py: read a vault's secrets as a Service Principal

This script uses the Azure SDK instead of the Azure CLI, so it needs two packages:

```bash
pip install azure-identity azure-keyvault-secrets
```

```bash
python3 kv_secret.py myvault --tenant-id <tenant-id> --credentials <client-id>:<client-secret>
```

| Option | Default | Description |
| --- | --- | --- |
| `name` | required | The vault name, as in `<name>.vault.azure.net`. |
| `--credentials` | required | The Service Principal's client ID and client secret, as `client_id:secret`. The secret may itself contain colons. |
| `--tenant-id` | `AZURE_TENANT_ID` | The Service Principal's tenant ID. Required if the environment variable is not set. |
| `--name-filter` | all secrets | Only show secrets whose name contains this text. The match ignores case. |
| `--preview` | off | Show the first 10 characters of each value and replace the rest with `*`. A value longer than 100 characters is cut off at 100 and ends with `...`. |

Each matching secret is printed as `name value`. Disabled secrets are listed as `<disabled>`, and secrets that can't be read print a warning and are skipped.

A secret passed on the command line is visible in your shell history and to other users on the machine through the process list, so prefer a short-lived secret or clear your history afterwards.

## Limitations

- Only **direct** assignments are found. Access a Service Principal gets through an Entra ID group is not reported.
- `kv_sp.py` lists every role assignment, including roles that give no Key Vault data access. It does not read access policies.
- ABAC conditions on role assignments are shown, but they are not evaluated.
- Management-plane permissions that could be used to gain access are not reported. For example, a Contributor on an access-policy vault can add an access policy for itself.
- Managed HSMs are not scanned.

The reports contain tenant, subscription and vault details, so store them with care.
