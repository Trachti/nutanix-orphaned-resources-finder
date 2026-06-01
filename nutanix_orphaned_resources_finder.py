import http.client
import json
import argparse
import ssl
from datetime import datetime, timezone, timedelta

NTNX_PRISMCENTRAL_IP = "YOUR_IP:9440"
PC_TOKEN = "YOUR GENERATED TOKEN FROM nutanix_auth.py"


def get_conn():
    context = ssl._create_unverified_context()
    return http.client.HTTPSConnection(NTNX_PRISMCENTRAL_IP, context=context)


def api_request(method, url, payload=None):
    conn = get_conn()
    headers = {
        "Accept": "application/json",
        "Authorization": PC_TOKEN,
        "Content-Type": "application/json"
    }

    body = None
    if payload is not None:
        body = payload if isinstance(payload, str) else json.dumps(payload)

    conn.request(method, url, body=body, headers=headers)
    res = conn.getresponse()
    raw = res.read().decode("utf-8")

    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        data = {"raw": raw}

    if res.status >= 400:
        raise RuntimeError(f"API error {res.status} on {url}: {data}")

    return data


def list_entities(kind, endpoint, page_size=100):
    offset = 0
    results = []

    while True:
        payload = {
            "kind": kind,
            "length": page_size,
            "offset": offset
        }

        data = api_request("POST", endpoint, payload)
        entities = data.get("entities", [])

        if not entities:
            break

        results.extend(entities)

        total_matches = data.get("metadata", {}).get("total_matches")
        offset += page_size

        if total_matches is not None and offset >= total_matches:
            break

    return results


def parse_datetime(value):
    if value in (None, ""):
        return None

    if isinstance(value, (int, float)):
        number = float(value)

        if number > 10_000_000_000_000:
            return datetime.fromtimestamp(number / 1_000_000, tz=timezone.utc)

        if number > 10_000_000_000:
            return datetime.fromtimestamp(number / 1000, tz=timezone.utc)

        return datetime.fromtimestamp(number, tz=timezone.utc)

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        try:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            return None

    return None


def get_vm_name(vm):
    return vm.get("spec", {}).get("name") or vm.get("status", {}).get("name")


def get_vm_uuid(vm):
    return vm.get("metadata", {}).get("uuid")


def get_vm_resources(vm):
    return vm.get("status", {}).get("resources") or vm.get("spec", {}).get("resources") or {}


def get_cluster_name(vm):
    cluster_ref = vm.get("status", {}).get("cluster_reference") or vm.get("spec", {}).get("cluster_reference") or {}
    return cluster_ref.get("name")


def get_power_state(vm):
    return get_vm_resources(vm).get("power_state")


def get_categories(vm):
    return vm.get("metadata", {}).get("categories") or {}


def get_project_reference(vm):
    return vm.get("metadata", {}).get("project_reference") or {}


def get_created_at(entity):
    metadata = entity.get("metadata", {})
    status = entity.get("status", {})

    candidates = [
        metadata.get("creation_time"),
        metadata.get("creationTime"),
        metadata.get("created_time"),
        metadata.get("createdTime"),
        status.get("creation_time"),
        status.get("creationTime"),
        status.get("created_time"),
        status.get("createdTime"),
    ]

    for value in candidates:
        parsed = parse_datetime(value)
        if parsed:
            return parsed

    return None


def get_subnet_uuid_from_nic(nic):
    subnet_ref = nic.get("subnet_reference") or {}
    return subnet_ref.get("uuid")


def get_used_subnet_uuids(vms):
    used = set()

    for vm in vms:
        resources = get_vm_resources(vm)
        for nic in resources.get("nic_list", []) or []:
            subnet_uuid = get_subnet_uuid_from_nic(nic)
            if subnet_uuid:
                used.add(subnet_uuid)

    return used


def get_subnet_info(subnet):
    metadata = subnet.get("metadata", {})
    spec = subnet.get("spec", {})
    status = subnet.get("status", {})
    resources = status.get("resources") or spec.get("resources") or {}

    cluster_ref = (
        status.get("cluster_reference")
        or spec.get("cluster_reference")
        or resources.get("cluster_reference")
        or {}
    )

    return {
        "name": spec.get("name") or status.get("name") or metadata.get("name"),
        "uuid": metadata.get("uuid"),
        "vlan_id": resources.get("vlan_id") or resources.get("vlanId"),
        "cluster_name": cluster_ref.get("name"),
        "cluster_uuid": cluster_ref.get("uuid"),
    }


def get_image_info(image):
    metadata = image.get("metadata", {})
    spec = image.get("spec", {})
    status = image.get("status", {})
    resources = status.get("resources") or spec.get("resources") or {}

    return {
        "name": spec.get("name") or status.get("name") or metadata.get("name"),
        "uuid": metadata.get("uuid"),
        "image_type": resources.get("image_type"),
        "state": resources.get("state"),
        "created_at": get_created_at(image),
    }


def find_vm_findings(vms, powered_off_days, include_missing_categories, include_missing_project):
    findings = []
    threshold = datetime.now(timezone.utc) - timedelta(days=powered_off_days)

    for vm in vms:
        name = get_vm_name(vm)
        vm_uuid = get_vm_uuid(vm)
        cluster_name = get_cluster_name(vm)
        power_state = str(get_power_state(vm) or "").upper()
        created_at = get_created_at(vm)
        categories = get_categories(vm)
        project_ref = get_project_reference(vm)

        if power_state == "OFF":
            if created_at and created_at < threshold:
                findings.append({
                    "type": "powered_off_vm",
                    "severity": "medium",
                    "name": name,
                    "uuid": vm_uuid,
                    "cluster": cluster_name,
                    "reason": f"VM is powered off and was created more than {powered_off_days} days ago.",
                    "created_at": created_at.isoformat(),
                })
            elif not created_at:
                findings.append({
                    "type": "powered_off_vm_unknown_age",
                    "severity": "low",
                    "name": name,
                    "uuid": vm_uuid,
                    "cluster": cluster_name,
                    "reason": "VM is powered off, but no creation timestamp was detected.",
                    "created_at": None,
                })

        if include_missing_categories and not categories:
            findings.append({
                "type": "vm_without_categories",
                "severity": "low",
                "name": name,
                "uuid": vm_uuid,
                "cluster": cluster_name,
                "reason": "VM has no categories assigned.",
                "created_at": created_at.isoformat() if created_at else None,
            })

        if include_missing_project and not project_ref:
            findings.append({
                "type": "vm_without_project",
                "severity": "low",
                "name": name,
                "uuid": vm_uuid,
                "cluster": cluster_name,
                "reason": "VM has no project reference assigned.",
                "created_at": created_at.isoformat() if created_at else None,
            })

    return findings


def find_unused_subnets(vms, subnets):
    findings = []
    used_subnet_uuids = get_used_subnet_uuids(vms)

    for subnet in subnets:
        info = get_subnet_info(subnet)
        subnet_uuid = info.get("uuid")

        if subnet_uuid and subnet_uuid not in used_subnet_uuids:
            findings.append({
                "type": "unused_subnet",
                "severity": "low",
                "name": info.get("name"),
                "uuid": subnet_uuid,
                "cluster": info.get("cluster_name"),
                "reason": "No VM NIC currently references this subnet.",
                "vlan_id": info.get("vlan_id"),
            })

    return findings


def find_images_without_clear_state(images):
    findings = []

    for image in images:
        info = get_image_info(image)
        state = str(info.get("state") or "").upper()

        if state and state not in {"ACTIVE", "COMPLETE", "AVAILABLE"}:
            findings.append({
                "type": "image_unusual_state",
                "severity": "medium",
                "name": info.get("name"),
                "uuid": info.get("uuid"),
                "cluster": None,
                "reason": f"Image has unusual state: {state}",
                "image_type": info.get("image_type"),
                "created_at": info.get("created_at").isoformat() if info.get("created_at") else None,
            })

    return findings


def print_findings(findings):
    print("\nNutanix Orphaned Resources Report")
    print("=================================")

    if not findings:
        print("No findings detected.")
        return

    for item in findings:
        print("-" * 80)
        print(f"Type: {item.get('type')}")
        print(f"Severity: {item.get('severity')}")
        print(f"Name: {item.get('name')}")
        print(f"UUID: {item.get('uuid')}")
        if item.get("cluster"):
            print(f"Cluster: {item.get('cluster')}")
        if item.get("vlan_id") is not None:
            print(f"VLAN ID: {item.get('vlan_id')}")
        if item.get("image_type"):
            print(f"Image type: {item.get('image_type')}")
        if item.get("created_at"):
            print(f"Created at: {item.get('created_at')}")
        print(f"Reason: {item.get('reason')}")

    print("-" * 80)
    print(f"Total findings: {len(findings)}")


def write_json(findings, output_file):
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "prism_central": NTNX_PRISMCENTRAL_IP,
        "finding_count": len(findings),
        "findings": findings
    }

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(output, file, indent=2, ensure_ascii=False)

    print(f"\nJSON report written to: {output_file}")


def write_markdown(findings, output_file):
    lines = []
    lines.append("# Nutanix Orphaned Resources Report")
    lines.append("")
    lines.append(f"Generated at: `{datetime.now(timezone.utc).isoformat()}`")
    lines.append("")
    lines.append(f"Finding count: **{len(findings)}**")
    lines.append("")

    if findings:
        lines.append("| Type | Severity | Name | UUID | Cluster | Reason |")
        lines.append("| --- | --- | --- | --- | --- | --- |")

        for item in findings:
            values = [
                item.get("type"),
                item.get("severity"),
                item.get("name"),
                item.get("uuid"),
                item.get("cluster"),
                item.get("reason"),
            ]
            clean_values = [str(value or "").replace("|", "\\|").replace("\n", " ") for value in values]
            lines.append("| " + " | ".join(clean_values) + " |")
    else:
        lines.append("No findings detected.")

    with open(output_file, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))
        file.write("\n")

    print(f"\nMarkdown report written to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Find potentially orphaned or unmanaged Nutanix resources from Prism Central."
    )
    parser.add_argument(
        "--powered-off-days",
        type=int,
        default=30,
        help="Flag powered-off VMs created more than this many days ago"
    )
    parser.add_argument(
        "--skip-missing-categories",
        action="store_true",
        help="Do not report VMs without categories"
    )
    parser.add_argument(
        "--skip-missing-project",
        action="store_true",
        help="Do not report VMs without a project reference"
    )
    parser.add_argument(
        "--skip-unused-subnets",
        action="store_true",
        help="Do not report subnets that are not referenced by VM NICs"
    )
    parser.add_argument(
        "--include-images",
        action="store_true",
        help="Also check images for unusual states"
    )
    parser.add_argument(
        "--json-file",
        required=False,
        help="Optional path for JSON report output"
    )
    parser.add_argument(
        "--markdown-file",
        required=False,
        help="Optional path for Markdown report output"
    )

    args = parser.parse_args()

    if args.powered_off_days < 1:
        raise ValueError("--powered-off-days must be at least 1")

    vms = list_entities("vm", "/api/nutanix/v3/vms/list")
    findings = []

    findings.extend(find_vm_findings(
        vms=vms,
        powered_off_days=args.powered_off_days,
        include_missing_categories=not args.skip_missing_categories,
        include_missing_project=not args.skip_missing_project,
    ))

    if not args.skip_unused_subnets:
        subnets = list_entities("subnet", "/api/nutanix/v3/subnets/list")
        findings.extend(find_unused_subnets(vms, subnets))

    if args.include_images:
        images = list_entities("image", "/api/nutanix/v3/images/list")
        findings.extend(find_images_without_clear_state(images))

    print_findings(findings)

    if args.json_file:
        write_json(findings, args.json_file)

    if args.markdown_file:
        write_markdown(findings, args.markdown_file)


if __name__ == "__main__":
    main()
