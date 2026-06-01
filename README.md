# Nutanix Orphaned Resources Finder

A Python script for finding potentially orphaned or unmanaged Nutanix resources from Prism Central.

This script does not delete anything. It only reports findings.

## Features

- Finds powered-off VMs older than a configurable number of days
- Finds VMs without categories
- Finds VMs without a project reference
- Finds subnets that are not referenced by any VM NIC
- Optionally checks images for unusual states
- Prints a readable report
- Can export findings as JSON
- Can export findings as Markdown
- Uses only the Python standard library

## Requirements

- Python 3.8 or newer
- Network access to Nutanix Prism Central
- A valid Nutanix Prism Central API token
- Permission to read VMs, subnets, and optionally images

No external Python packages are required.

## Configuration

Before running the script, update these values in `nutanix_orphaned_resources_finder.py`:

```python
NTNX_PRISMCENTRAL_IP = "YOUR_IP:9440"
PC_TOKEN = "YOUR GENERATED TOKEN FROM nutanix_auth.py"
```

## Usage

Run with default checks:

```bash
python nutanix_orphaned_resources_finder.py
```

Flag powered-off VMs older than 60 days:

```bash
python nutanix_orphaned_resources_finder.py --powered-off-days 60
```

Skip VM category checks:

```bash
python nutanix_orphaned_resources_finder.py --skip-missing-categories
```

Skip VM project checks:

```bash
python nutanix_orphaned_resources_finder.py --skip-missing-project
```

Skip unused subnet checks:

```bash
python nutanix_orphaned_resources_finder.py --skip-unused-subnets
```

Include image state checks:

```bash
python nutanix_orphaned_resources_finder.py --include-images
```

Write reports:

```bash
python nutanix_orphaned_resources_finder.py \
  --json-file orphaned-resources.json \
  --markdown-file orphaned-resources.md
```

## Arguments

| Argument | Required | Description |
|---|---:|---|
| `--powered-off-days` | No | Age threshold for powered-off VMs, default `30` |
| `--skip-missing-categories` | No | Do not report VMs without categories |
| `--skip-missing-project` | No | Do not report VMs without a project reference |
| `--skip-unused-subnets` | No | Do not report unused subnets |
| `--include-images` | No | Also check images for unusual states |
| `--json-file` | No | Write JSON report |
| `--markdown-file` | No | Write Markdown report |

## Finding Types

The script can report:

```text
powered_off_vm
powered_off_vm_unknown_age
vm_without_categories
vm_without_project
unused_subnet
image_unusual_state
```

## Safety Notes

This script is read-only. It does not delete, modify, power off, or power on any resources.

## Security Notes

Do not commit real API tokens, passwords, Prism Central addresses, generated reports, or internal infrastructure details to a public GitHub repository.

The script currently disables SSL certificate verification by using:

```python
ssl._create_unverified_context()
```

This may be useful in lab environments, but it is not recommended for production. For production use, configure proper certificate validation.

## Disclaimer

This script is provided as an example. Test it in a safe environment before using it against production Nutanix infrastructure.
