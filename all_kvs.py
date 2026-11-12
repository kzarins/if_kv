#!/usr/bin/env python3

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


KEY_VAULT_DATA_ACTION_PREFIX = "microsoft.keyvault/vaults/"
KEY_VAULT_PROVIDER_PATH = "/providers/microsoft.keyvault/vaults/"


def run_az(
    arguments: List[str],
    allow_failure: bool = False,
) -> Optional[Any]:
    """
    Run an Azure CLI command and return decoded JSON.
    """

    command = ["az"] + arguments + ["--output", "json"]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        print(
            "ERROR: Azure CLI was not found. "
            "Install Azure CLI and ensure 'az' is available in PATH.",
            file=sys.stderr,
        )
        sys.exit(1)

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip()

        if allow_failure:
            print(
                f"WARNING: Command failed: {' '.join(command)}",
                file=sys.stderr,
            )

            if error:
                print(f"         {error}", file=sys.stderr)

            return None

        print(
            f"ERROR: Command failed: {' '.join(command)}",
            file=sys.stderr,
        )

        if error:
            print(error, file=sys.stderr)

        sys.exit(result.returncode)

    output = result.stdout.strip()

    if not output:
        return None

    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        print(
            f"ERROR: Azure CLI returned invalid JSON: {exc}",
            file=sys.stderr,
        )
        print(output, file=sys.stderr)
        sys.exit(1)


def normalize_resource_id(resource_id: Optional[str]) -> str:
    """
    Normalize an Azure resource ID for case-insensitive comparisons.
    """

    if not resource_id:
        return ""

    return resource_id.strip().rstrip("/").lower()


def normalize_guid(value: Optional[str]) -> str:
    """
    Normalize a GUID or object ID for comparison.
    """

    if not value:
        return ""

    return value.strip().lower()


def read_client_ids(file_path: Path) -> List[str]:
    """
    Read unique SP client IDs from a file.

    Supported format:
      - One client ID per line
      - Empty lines are ignored
      - Lines beginning with # are ignored
      - Inline comments beginning with # are removed
    """

    if not file_path.exists():
        print(
            f"ERROR: Client ID file does not exist: {file_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    client_ids: List[str] = []
    seen: Set[str] = set()

    try:
        with file_path.open("r", encoding="utf-8-sig") as input_file:
            for line_number, raw_line in enumerate(input_file, start=1):
                value = raw_line.split("#", maxsplit=1)[0].strip()

                if not value:
                    continue

                normalized = value.lower()

                if normalized in seen:
                    continue

                seen.add(normalized)
                client_ids.append(value)

    except OSError as exc:
        print(
            f"ERROR: Could not read client ID file: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not client_ids:
        print(
            "ERROR: No client IDs were found in the input file.",
            file=sys.stderr,
        )
        sys.exit(1)

    return client_ids


def resolve_service_principals(
    client_ids: List[str],
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """
    Resolve client IDs to Service Principal object IDs.

    Returns:
      - successfully resolved Service Principals
      - unresolved client IDs with error information
    """

    service_principals: List[Dict[str, str]] = []
    unresolved: List[Dict[str, str]] = []

    for index, client_id in enumerate(client_ids, start=1):
        print(
            f"Resolving Service Principal "
            f"[{index}/{len(client_ids)}]: {client_id}"
        )

        sp = run_az(
            [
                "ad",
                "sp",
                "show",
                "--id",
                client_id,
            ],
            allow_failure=True,
        )

        if not isinstance(sp, dict):
            unresolved.append(
                {
                    "clientId": client_id,
                    "error": "Service Principal was not found or could not be read",
                }
            )
            continue

        object_id = sp.get("id")
        app_id = sp.get("appId")

        if not object_id or not app_id:
            unresolved.append(
                {
                    "clientId": client_id,
                    "error": "Service Principal response did not contain id/appId",
                }
            )
            continue

        service_principals.append(
            {
                "displayName": str(sp.get("displayName", "")),
                "clientId": str(app_id),
                "objectId": str(object_id),
                "servicePrincipalType": str(
                    sp.get("servicePrincipalType", "")
                ),
            }
        )

    return service_principals, unresolved


def get_subscriptions() -> List[Dict[str, Any]]:
    """
    Return all enabled subscriptions visible to the Azure CLI identity.
    """

    subscriptions = run_az(
        [
            "account",
            "list",
            "--all",
        ]
    )

    if not isinstance(subscriptions, list):
        return []

    enabled = [
        subscription
        for subscription in subscriptions
        if str(subscription.get("state", "")).casefold() == "enabled"
    ]

    return sorted(
        enabled,
        key=lambda item: str(item.get("name", "")).casefold(),
    )


def get_key_vaults(
    subscription_id: str,
) -> Optional[List[Dict[str, Any]]]:
    """
    Enumerate visible Key Vaults in a subscription.
    """

    vaults = run_az(
        [
            "keyvault",
            "list",
            "--subscription",
            subscription_id,
        ],
        allow_failure=True,
    )

    if vaults is None:
        return None

    if not isinstance(vaults, list):
        return []

    return vaults


def get_key_vault_details(
    vault_name: str,
    subscription_id: str,
) -> Optional[Dict[str, Any]]:
    """
    Get the Key Vault configuration, including its authorization model
    and legacy access policies.
    """

    vault = run_az(
        [
            "keyvault",
            "show",
            "--name",
            vault_name,
            "--subscription",
            subscription_id,
        ],
        allow_failure=True,
    )

    if not isinstance(vault, dict):
        return None

    return vault


def get_role_assignments(
    subscription_id: str,
) -> Optional[List[Dict[str, Any]]]:
    """
    Retrieve RBAC assignments from the subscription and applicable
    inherited scopes.
    """

    assignments = run_az(
        [
            "role",
            "assignment",
            "list",
            "--subscription",
            subscription_id,
            "--include-inherited",
            "--all",
        ],
        allow_failure=True,
    )

    if assignments is None:
        return None

    if not isinstance(assignments, list):
        return []

    return assignments


def get_role_definitions(
    subscription_id: str,
) -> Optional[List[Dict[str, Any]]]:
    """
    Retrieve built-in and custom role definitions visible in a subscription.
    """

    roles = run_az(
        [
            "role",
            "definition",
            "list",
            "--subscription",
            subscription_id,
        ],
        allow_failure=True,
    )

    if roles is None:
        return None

    if not isinstance(roles, list):
        return []

    return roles


def build_role_definition_map(
    role_definitions: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """
    Create a lookup map for role definitions using both the full resource ID
    and the role-definition GUID.
    """

    role_map: Dict[str, Dict[str, Any]] = {}

    for role in role_definitions:
        role_id = normalize_resource_id(
            str(role.get("id", ""))
        )

        role_guid = normalize_guid(
            str(role.get("name", ""))
        )

        if role_id:
            role_map[role_id] = role

        if role_guid:
            role_map[role_guid] = role

    return role_map


def get_role_definition(
    assignment: Dict[str, Any],
    role_map: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Resolve the role definition associated with a role assignment.
    """

    role_definition_id = str(
        assignment.get("roleDefinitionId", "")
    )

    normalized_role_id = normalize_resource_id(role_definition_id)

    if normalized_role_id in role_map:
        return role_map[normalized_role_id]

    role_guid = normalize_guid(
        role_definition_id.rstrip("/").split("/")[-1]
    )

    return role_map.get(role_guid)


def flatten_role_permissions(
    role_definition: Optional[Dict[str, Any]],
) -> Tuple[List[str], List[str]]:
    """
    Return normalized dataActions and notDataActions for a role.
    """

    if not role_definition:
        return [], []

    data_actions: List[str] = []
    not_data_actions: List[str] = []

    for permission_block in role_definition.get("permissions", []):
        for action in permission_block.get("dataActions", []):
            data_actions.append(str(action).lower())

        for action in permission_block.get("notDataActions", []):
            not_data_actions.append(str(action).lower())

    return data_actions, not_data_actions


def action_matches(
    granted_action: str,
    requested_action: str,
) -> bool:
    """
    Determine whether an Azure RBAC data action matches a requested action.

    This handles:
      *
      Microsoft.KeyVault/*
      Microsoft.KeyVault/vaults/*
      exact actions
      prefix wildcard actions
    """

    granted = granted_action.strip().lower()
    requested = requested_action.strip().lower()

    if granted == "*":
        return True

    if granted.endswith("*"):
        return requested.startswith(granted[:-1])

    return granted == requested


def role_allows_action(
    role_definition: Optional[Dict[str, Any]],
    requested_action: str,
) -> bool:
    """
    Determine whether a role grants a data-plane action after considering
    notDataActions.
    """

    data_actions, not_data_actions = flatten_role_permissions(
        role_definition
    )

    granted = any(
        action_matches(action, requested_action)
        for action in data_actions
    )

    denied = any(
        action_matches(action, requested_action)
        for action in not_data_actions
    )

    return granted and not denied


def get_key_vault_capabilities(
    role_definition: Optional[Dict[str, Any]],
) -> List[str]:
    """
    Determine which Key Vault data-plane capabilities a role provides.

    The capability labels represent practical operation categories rather
    than every individual Azure action.
    """

    capability_actions = {
        "Secrets: Get": (
            "microsoft.keyvault/vaults/secrets/getsecret/action"
        ),
        "Secrets: List": (
            "microsoft.keyvault/vaults/secrets/readmetadata/action"
        ),
        "Secrets: Set": (
            "microsoft.keyvault/vaults/secrets/setsecret/action"
        ),
        "Secrets: Delete": (
            "microsoft.keyvault/vaults/secrets/delete"
        ),
        "Keys: Read": (
            "microsoft.keyvault/vaults/keys/read"
        ),
        "Keys: Encrypt": (
            "microsoft.keyvault/vaults/keys/encrypt/action"
        ),
        "Keys: Decrypt": (
            "microsoft.keyvault/vaults/keys/decrypt/action"
        ),
        "Keys: Sign": (
            "microsoft.keyvault/vaults/keys/sign/action"
        ),
        "Keys: Verify": (
            "microsoft.keyvault/vaults/keys/verify/action"
        ),
        "Certificates: Read": (
            "microsoft.keyvault/vaults/certificates/read"
        ),
    }

    capabilities = []

    for label, requested_action in capability_actions.items():
        if role_allows_action(role_definition, requested_action):
            capabilities.append(label)

    return capabilities


def assignment_scope_relationship(
    assignment_scope: Optional[str],
    vault_resource_id: Optional[str],
) -> Optional[str]:
    """
    Determine whether an RBAC assignment applies to a Key Vault.

    Returns:
      direct-vault
      inherited-parent
      child-resource-only
      None
    """

    scope = normalize_resource_id(assignment_scope)
    vault_id = normalize_resource_id(vault_resource_id)

    if not scope or not vault_id:
        return None

    if scope == vault_id:
        return "direct-vault"

    if vault_id.startswith(scope + "/"):
        return "inherited-parent"

    if scope.startswith(vault_id + "/"):
        return "child-resource-only"

    return None


def get_legacy_policy_capabilities(
    policy: Dict[str, Any],
) -> List[str]:
    """
    Convert legacy Key Vault access-policy permissions to readable labels.
    """

    permissions = policy.get("permissions", {})

    if not isinstance(permissions, dict):
        return []

    capabilities: List[str] = []

    secret_permissions = permissions.get("secrets") or []
    key_permissions = permissions.get("keys") or []
    certificate_permissions = permissions.get("certificates") or []
    storage_permissions = permissions.get("storage") or []

    for permission in secret_permissions:
        capabilities.append(
            f"Secrets: {str(permission).capitalize()}"
        )

    for permission in key_permissions:
        capabilities.append(
            f"Keys: {str(permission).capitalize()}"
        )

    for permission in certificate_permissions:
        capabilities.append(
            f"Certificates: {str(permission).capitalize()}"
        )

    for permission in storage_permissions:
        capabilities.append(
            f"Storage: {str(permission).capitalize()}"
        )

    return sorted(set(capabilities))


def find_legacy_access(
    service_principals_by_object_id: Dict[str, Dict[str, str]],
    vault_details: Dict[str, Any],
    subscription_name: str,
    subscription_id: str,
) -> List[Dict[str, Any]]:
    """
    Find legacy Key Vault access policies assigned directly to the supplied
    Service Principals.
    """

    results: List[Dict[str, Any]] = []

    properties = vault_details.get("properties", {})
    access_policies = properties.get("accessPolicies") or []

    vault_name = str(vault_details.get("name", "Unknown"))
    vault_id = str(vault_details.get("id", ""))
    resource_group = str(vault_details.get("resourceGroup", ""))

    for policy in access_policies:
        object_id = normalize_guid(
            str(policy.get("objectId", ""))
        )

        sp = service_principals_by_object_id.get(object_id)

        if not sp:
            continue

        capabilities = get_legacy_policy_capabilities(policy)

        if not capabilities:
            continue

        results.append(
            {
                "servicePrincipalName": sp["displayName"],
                "clientId": sp["clientId"],
                "objectId": sp["objectId"],
                "subscriptionName": subscription_name,
                "subscriptionId": subscription_id,
                "keyVaultName": vault_name,
                "resourceGroup": resource_group,
                "keyVaultResourceId": vault_id,
                "authorizationModel": "Access policy",
                "roleOrPolicy": "Legacy Key Vault access policy",
                "assignmentScope": vault_id,
                "scopeRelationship": "direct-vault",
                "capabilities": capabilities,
                "condition": None,
            }
        )

    return results


def find_rbac_access(
    service_principals_by_object_id: Dict[str, Dict[str, str]],
    assignments: List[Dict[str, Any]],
    role_map: Dict[str, Dict[str, Any]],
    vault_details: Dict[str, Any],
    subscription_name: str,
    subscription_id: str,
) -> List[Dict[str, Any]]:
    """
    Find RBAC assignments that grant Key Vault data-plane access.
    """

    results: List[Dict[str, Any]] = []

    vault_name = str(vault_details.get("name", "Unknown"))
    vault_id = str(vault_details.get("id", ""))
    resource_group = str(vault_details.get("resourceGroup", ""))

    for assignment in assignments:
        principal_id = normalize_guid(
            str(assignment.get("principalId", ""))
        )

        sp = service_principals_by_object_id.get(principal_id)

        if not sp:
            continue

        relationship = assignment_scope_relationship(
            assignment.get("scope"),
            vault_id,
        )

        if not relationship:
            continue

        role_definition = get_role_definition(
            assignment,
            role_map,
        )

        capabilities = get_key_vault_capabilities(
            role_definition
        )

        if not capabilities:
            continue

        role_name = str(
            assignment.get("roleDefinitionName", "")
        )

        if not role_name and role_definition:
            role_name = str(
                role_definition.get("roleName", "Unknown")
            )

        results.append(
            {
                "servicePrincipalName": sp["displayName"],
                "clientId": sp["clientId"],
                "objectId": sp["objectId"],
                "subscriptionName": subscription_name,
                "subscriptionId": subscription_id,
                "keyVaultName": vault_name,
                "resourceGroup": resource_group,
                "keyVaultResourceId": vault_id,
                "authorizationModel": "Azure RBAC",
                "roleOrPolicy": role_name or "Unknown role",
                "assignmentScope": str(
                    assignment.get("scope", "")
                ),
                "scopeRelationship": relationship,
                "capabilities": capabilities,
                "condition": assignment.get("condition"),
            }
        )

    return results


def deduplicate_results(
    results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Remove duplicate report entries.
    """

    unique_results: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, ...]] = set()

    for result in results:
        key = (
            normalize_guid(result.get("objectId")),
            normalize_resource_id(
                result.get("keyVaultResourceId")
            ),
            str(result.get("authorizationModel", "")),
            str(result.get("roleOrPolicy", "")),
            normalize_resource_id(
                result.get("assignmentScope")
            ),
            "|".join(result.get("capabilities", [])),
        )

        if key in seen:
            continue

        seen.add(key)
        unique_results.append(result)

    return sorted(
        unique_results,
        key=lambda item: (
            str(item.get("servicePrincipalName", "")).casefold(),
            str(item.get("subscriptionName", "")).casefold(),
            str(item.get("keyVaultName", "")).casefold(),
            str(item.get("authorizationModel", "")).casefold(),
            str(item.get("roleOrPolicy", "")).casefold(),
        ),
    )


def write_csv_report(
    output_path: Path,
    results: List[Dict[str, Any]],
) -> None:
    """
    Write a flattened CSV report.
    """

    fieldnames = [
        "servicePrincipalName",
        "clientId",
        "objectId",
        "subscriptionName",
        "subscriptionId",
        "keyVaultName",
        "resourceGroup",
        "authorizationModel",
        "roleOrPolicy",
        "scopeRelationship",
        "assignmentScope",
        "capabilities",
        "condition",
        "keyVaultResourceId",
    ]

    try:
        with output_path.open(
            "w",
            encoding="utf-8-sig",
            newline="",
        ) as output_file:
            writer = csv.DictWriter(
                output_file,
                fieldnames=fieldnames,
            )

            writer.writeheader()

            for result in results:
                row = dict(result)
                row["capabilities"] = "; ".join(
                    result.get("capabilities", [])
                )
                writer.writerow(row)

    except OSError as exc:
        print(
            f"ERROR: Could not write CSV report: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)


def write_json_report(
    output_path: Path,
    service_principals: List[Dict[str, str]],
    unresolved: List[Dict[str, str]],
    results: List[Dict[str, Any]],
    scan_errors: List[Dict[str, str]],
) -> None:
    """
    Write the detailed JSON report.
    """

    report = {
        "servicePrincipals": service_principals,
        "unresolvedClientIds": unresolved,
        "access": results,
        "scanErrors": scan_errors,
    }

    try:
        with output_path.open(
            "w",
            encoding="utf-8",
        ) as output_file:
            json.dump(
                report,
                output_file,
                indent=2,
                ensure_ascii=False,
            )
            output_file.write("\n")

    except OSError as exc:
        print(
            f"ERROR: Could not write JSON report: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)


def print_access_result(result: Dict[str, Any]) -> None:
    """
    Print an access result to the console.
    """

    print(
        f"    {result['servicePrincipalName']} "
        f"({result['clientId']})"
    )
    print(
        f"      Authorization: "
        f"{result['authorizationModel']}"
    )
    print(
        f"      Role/policy:   "
        f"{result['roleOrPolicy']}"
    )
    print(
        f"      Relationship:  "
        f"{result['scopeRelationship']}"
    )
    print(
        f"      Capabilities:  "
        f"{', '.join(result['capabilities'])}"
    )

    if result.get("condition"):
        print(
            f"      Condition:     "
            f"{result['condition']}"
        )

    print(
        f"      Scope:         "
        f"{result['assignmentScope']}"
    )
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Read Service Principal client IDs from a file, scan all "
            "accessible Azure subscriptions, and report which Service "
            "Principals have direct RBAC or legacy access-policy access "
            "to which Azure Key Vaults."
        )
    )

    parser.add_argument(
        "--client-ids-file",
        required=True,
        type=Path,
        help=(
            "Text file containing one Service Principal client ID per line."
        ),
    )

    parser.add_argument(
        "--csv-report",
        type=Path,
        default=Path("sp_keyvault_access_report.csv"),
        help=(
            "CSV report path. Default: sp_keyvault_access_report.csv"
        ),
    )

    parser.add_argument(
        "--json-report",
        type=Path,
        default=Path("sp_keyvault_access_report.json"),
        help=(
            "JSON report path. Default: sp_keyvault_access_report.json"
        ),
    )

    args = parser.parse_args()

    current_account = run_az(
        ["account", "show"],
        allow_failure=True,
    )

    if current_account is None:
        print(
            "ERROR: No active Azure CLI session was found. "
            "Run 'az login' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    client_ids = read_client_ids(
        args.client_ids_file
    )

    service_principals, unresolved = (
        resolve_service_principals(client_ids)
    )

    if not service_principals:
        print(
            "ERROR: None of the supplied client IDs could be resolved.",
            file=sys.stderr,
        )
        sys.exit(1)

    service_principals_by_object_id = {
        normalize_guid(sp["objectId"]): sp
        for sp in service_principals
    }

    subscriptions = get_subscriptions()

    if not subscriptions:
        print(
            "ERROR: No enabled Azure subscriptions are available.",
            file=sys.stderr,
        )
        sys.exit(1)

    print()
    print(
        f"Resolved {len(service_principals)} Service Principal(s)."
    )

    if unresolved:
        print(
            f"Could not resolve {len(unresolved)} client ID(s)."
        )

    print(
        f"Scanning {len(subscriptions)} enabled subscription(s)."
    )
    print()

    access_results: List[Dict[str, Any]] = []
    scan_errors: List[Dict[str, str]] = []

    for subscription_index, subscription in enumerate(
        subscriptions,
        start=1,
    ):
        subscription_name = str(
            subscription.get("name", "Unknown")
        )
        subscription_id = str(
            subscription.get("id", "")
        )

        print(
            f"[{subscription_index}/{len(subscriptions)}] "
            f"{subscription_name} ({subscription_id})"
        )

        vaults = get_key_vaults(subscription_id)

        if vaults is None:
            message = "Could not enumerate Key Vaults"

            print(f"  WARNING: {message}.")
            print()

            scan_errors.append(
                {
                    "subscriptionName": subscription_name,
                    "subscriptionId": subscription_id,
                    "resource": "",
                    "error": message,
                }
            )
            continue

        if not vaults:
            print("  No visible Key Vaults.")
            print()
            continue

        assignments = get_role_assignments(
            subscription_id
        )

        if assignments is None:
            assignments = []

            scan_errors.append(
                {
                    "subscriptionName": subscription_name,
                    "subscriptionId": subscription_id,
                    "resource": "",
                    "error": "Could not retrieve RBAC assignments",
                }
            )

        role_definitions = get_role_definitions(
            subscription_id
        )

        if role_definitions is None:
            role_definitions = []

            scan_errors.append(
                {
                    "subscriptionName": subscription_name,
                    "subscriptionId": subscription_id,
                    "resource": "",
                    "error": "Could not retrieve role definitions",
                }
            )

        role_map = build_role_definition_map(
            role_definitions
        )

        print(f"  Key Vaults: {len(vaults)}")

        for vault_index, vault in enumerate(
            vaults,
            start=1,
        ):
            vault_name = str(
                vault.get("name", "Unknown")
            )

            print(
                f"  [{vault_index}/{len(vaults)}] "
                f"{vault_name}"
            )

            vault_details = get_key_vault_details(
                vault_name,
                subscription_id,
            )

            if vault_details is None:
                print(
                    "    WARNING: Could not retrieve vault details."
                )

                scan_errors.append(
                    {
                        "subscriptionName": subscription_name,
                        "subscriptionId": subscription_id,
                        "resource": vault_name,
                        "error": "Could not retrieve Key Vault details",
                    }
                )
                continue

            properties = vault_details.get(
                "properties",
                {},
            )

            uses_rbac = bool(
                properties.get(
                    "enableRbacAuthorization",
                    False,
                )
            )

            if uses_rbac:
                vault_results = find_rbac_access(
                    service_principals_by_object_id,
                    assignments,
                    role_map,
                    vault_details,
                    subscription_name,
                    subscription_id,
                )
            else:
                vault_results = find_legacy_access(
                    service_principals_by_object_id,
                    vault_details,
                    subscription_name,
                    subscription_id,
                )

            if not vault_results:
                print(
                    "    No direct access found for the supplied "
                    "Service Principals."
                )
                continue

            for result in vault_results:
                print_access_result(result)

            access_results.extend(vault_results)

        print()

    access_results = deduplicate_results(
        access_results
    )

    write_csv_report(
        args.csv_report,
        access_results,
    )

    write_json_report(
        args.json_report,
        service_principals,
        unresolved,
        access_results,
        scan_errors,
    )

    print(f"CSV report:  {args.csv_report}")
    print(f"JSON report: {args.json_report}")


if __name__ == "__main__":
    main()