#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
from typing import Any, Optional


KEY_VAULT_PROVIDER_PATH = "/providers/microsoft.keyvault/vaults/"


def run_az(
    arguments: list[str],
    *,
    allow_failure: bool = False,
) -> Optional[Any]:
    """Run Azure CLI and return decoded JSON."""

    command = ["az", *arguments, "--output", "json"]

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
            "Make sure 'az' is installed and available in PATH.",
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
            print(f"         {error}", file=sys.stderr)
            return None

        print(
            f"ERROR: Command failed: {' '.join(command)}",
            file=sys.stderr,
        )
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
    """Normalize an Azure resource ID for comparisons."""

    if not resource_id:
        return ""

    return resource_id.strip().rstrip("/").lower()


def get_service_principal(client_id: str) -> dict[str, str]:
    """Resolve Client ID to Service Principal Object ID."""

    sp = run_az(
        [
            "ad",
            "sp",
            "show",
            "--id",
            client_id,
        ]
    )

    if not isinstance(sp, dict):
        print(
            f"ERROR: Service Principal not found for Client ID: {client_id}",
            file=sys.stderr,
        )
        sys.exit(1)

    object_id = sp.get("id")
    app_id = sp.get("appId")

    if not object_id or not app_id:
        print(
            "ERROR: Service Principal response does not contain "
            "the expected id/appId fields.",
            file=sys.stderr,
        )
        sys.exit(1)

    return {
        "objectId": object_id,
        "clientId": app_id,
        "displayName": sp.get("displayName", ""),
    }


def get_matching_subscriptions(
    subscription_name_filter: str,
) -> list[dict[str, Any]]:
    """Get enabled subscriptions containing the specified string."""

    subscriptions = run_az(
        [
            "account",
            "list",
            "--all",
        ]
    )

    if not isinstance(subscriptions, list):
        return []

    search_value = subscription_name_filter.casefold()

    matching = [
        subscription
        for subscription in subscriptions
        if search_value
        in str(subscription.get("name", "")).casefold()
        and str(subscription.get("state", "")).casefold() == "enabled"
    ]

    return sorted(
        matching,
        key=lambda item: str(item.get("name", "")).casefold(),
    )


def get_role_assignments(
    object_id: str,
    subscription_id: str,
) -> Optional[list[dict[str, Any]]]:
    """
    Get direct and inherited Azure RBAC assignments for
    the Service Principal.
    """

    assignments = run_az(
        [
            "role",
            "assignment",
            "list",
            "--assignee-object-id",
            object_id,
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


def get_key_vaults(
    subscription_id: str,
) -> Optional[list[dict[str, Any]]]:
    """List all visible Key Vaults in the subscription."""

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


def extract_key_vault_name_from_scope(
    assignment_scope: Optional[str],
) -> Optional[str]:
    """
    Extract the Key Vault name if the assignment scope points
    directly to a Key Vault or one of its child resources.
    """

    normalized_scope = normalize_resource_id(assignment_scope)

    marker_position = normalized_scope.find(
        KEY_VAULT_PROVIDER_PATH
    )

    if marker_position == -1:
        return None

    name_start = (
        marker_position
        + len(KEY_VAULT_PROVIDER_PATH)
    )

    remaining_scope = normalized_scope[name_start:]

    if not remaining_scope:
        return None

    return remaining_scope.split("/", maxsplit=1)[0]


def correlate_assignment_with_vault(
    assignment_scope: Optional[str],
    vault_resource_id: Optional[str],
) -> Optional[str]:
    """
    Determine whether an RBAC assignment applies to a Key Vault.

    Returns:
        direct-vault
            Assignment is directly on the Key Vault.

        inherited-parent
            Assignment is on a parent scope, such as the
            resource group or subscription.

        child-resource-only
            Assignment is below the Key Vault, such as a
            specific secret, key, or certificate.

        None
            Assignment does not relate to this Key Vault.
    """

    normalized_scope = normalize_resource_id(
        assignment_scope
    )

    normalized_vault_id = normalize_resource_id(
        vault_resource_id
    )

    if not normalized_scope or not normalized_vault_id:
        return None

    if normalized_scope == normalized_vault_id:
        return "direct-vault"

    if normalized_vault_id.startswith(
        normalized_scope + "/"
    ):
        return "inherited-parent"

    if normalized_scope.startswith(
        normalized_vault_id + "/"
    ):
        return "child-resource-only"

    return None


def get_vault_matches(
    assignment: dict[str, Any],
    vaults: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Find Key Vaults related to an RBAC assignment."""

    assignment_scope = assignment.get("scope")
    matches = []

    for vault in vaults:
        vault_id = vault.get("id")

        relationship = correlate_assignment_with_vault(
            assignment_scope,
            vault_id,
        )

        if relationship:
            matches.append(
                {
                    "name": str(
                        vault.get("name", "Unknown")
                    ),
                    "resourceGroup": str(
                        vault.get(
                            "resourceGroup",
                            "Unknown",
                        )
                    ),
                    "resourceId": str(
                        vault_id or "Unknown"
                    ),
                    "relationship": relationship,
                }
            )

    return sorted(
        matches,
        key=lambda item: item["name"].casefold(),
    )


def print_service_principal(
    sp: dict[str, str],
) -> None:
    """Print Service Principal information."""

    print("SERVICE PRINCIPAL")
    print(f"Name:      {sp['displayName']}")
    print(f"Client ID: {sp['clientId']}")
    print(f"Object ID: {sp['objectId']}")
    print()


def print_assignment(
    number: int,
    assignment: dict[str, Any],
    vault_matches: list[dict[str, str]],
) -> None:
    """Print one RBAC assignment and related Key Vaults."""

    role_name = assignment.get(
        "roleDefinitionName",
        "Unknown",
    )

    scope = assignment.get(
        "scope",
        "Unknown",
    )

    principal_type = assignment.get(
        "principalType",
        "Unknown",
    )

    condition = assignment.get("condition")

    direct_vault_name = extract_key_vault_name_from_scope(
        scope
    )

    print(f"  Assignment {number}")
    print(f"    Role:           {role_name}")
    print(f"    Principal type: {principal_type}")
    print(f"    Scope:          {scope}")

    if condition:
        print(f"    Condition:      {condition}")

    if direct_vault_name:
        print(f"    KV in scope:    {direct_vault_name}")

    if vault_matches:
        print("    Related Key Vaults:")

        for vault in vault_matches:
            print(
                f"      - {vault['name']} "
                f"[{vault['relationship']}]"
            )

            print(
                f"        Resource group: "
                f"{vault['resourceGroup']}"
            )

            print(
                f"        Resource ID:    "
                f"{vault['resourceId']}"
            )

    else:
        print("    Related Key Vaults: None found")

    print()


def build_json_result(
    sp: dict[str, str],
    subscription_filter: str,
    subscription_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build optional JSON result."""

    return {
        "servicePrincipal": sp,
        "subscriptionFilter": subscription_filter,
        "subscriptions": subscription_results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Find Azure RBAC assignments for a Service Principal "
            "across subscriptions matching a name and correlate "
            "the assignments with Azure Key Vaults."
        )
    )

    parser.add_argument(
        "--client-id",
        required=True,
        help="Application/Client ID of the Service Principal.",
    )

    parser.add_argument(
        "--subscription-filter",
        required=True,
        help=(
            "Case-insensitive string that must occur "
            "in the subscription name."
        ),
    )

    parser.add_argument(
        "--json-file",
        help="Optional path to save the complete result as JSON.",
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

    sp = get_service_principal(args.client_id)

    print_service_principal(sp)

    subscriptions = get_matching_subscriptions(
        args.subscription_filter
    )

    if not subscriptions:
        print(
            "No enabled subscriptions were found containing "
            f"'{args.subscription_filter}'."
        )
        sys.exit(0)

    print(
        f"Found {len(subscriptions)} enabled subscription(s) "
        f"containing '{args.subscription_filter}'."
    )
    print()

    subscription_results = []

    for index, subscription in enumerate(
        subscriptions,
        start=1,
    ):
        subscription_id = str(
            subscription.get("id", "")
        )

        subscription_name = str(
            subscription.get("name", "Unknown")
        )

        print(
            f"[{index}/{len(subscriptions)}] "
            f"{subscription_name} ({subscription_id})"
        )
        print()

        assignments = get_role_assignments(
            sp["objectId"],
            subscription_id,
        )

        vaults = get_key_vaults(
            subscription_id
        )

        result_entry: dict[str, Any] = {
            "subscriptionName": subscription_name,
            "subscriptionId": subscription_id,
            "keyVaultEnumerationSucceeded": vaults is not None,
            "roleAssignmentQuerySucceeded": assignments is not None,
            "assignments": [],
        }

        if assignments is None:
            print(
                "  Role-assignment query failed "
                "for this subscription."
            )
            print()

            subscription_results.append(
                result_entry
            )
            continue

        if vaults is None:
            print(
                "  WARNING: Key Vault enumeration failed. "
                "Role assignments will be shown without "
                "complete Key Vault correlation."
            )

            vaults = []

        print(
            f"  Visible Key Vaults: {len(vaults)}"
        )

        if not assignments:
            print(
                "  No direct or inherited RBAC assignments "
                "were found for this Service Principal."
            )
            print()

            subscription_results.append(
                result_entry
            )
            continue

        print(
            f"  RBAC assignments found: {len(assignments)}"
        )
        print()

        sorted_assignments = sorted(
            assignments,
            key=lambda item: (
                str(
                    item.get(
                        "roleDefinitionName",
                        "",
                    )
                ).casefold(),
                str(
                    item.get(
                        "scope",
                        "",
                    )
                ).casefold(),
            ),
        )

        for assignment_number, assignment in enumerate(
            sorted_assignments,
            start=1,
        ):
            vault_matches = get_vault_matches(
                assignment,
                vaults,
            )

            print_assignment(
                assignment_number,
                assignment,
                vault_matches,
            )

            result_entry["assignments"].append(
                {
                    "roleDefinitionName": assignment.get(
                        "roleDefinitionName"
                    ),
                    "roleDefinitionId": assignment.get(
                        "roleDefinitionId"
                    ),
                    "scope": assignment.get(
                        "scope"
                    ),
                    "principalId": assignment.get(
                        "principalId"
                    ),
                    "principalType": assignment.get(
                        "principalType"
                    ),
                    "condition": assignment.get(
                        "condition"
                    ),
                    "conditionVersion": assignment.get(
                        "conditionVersion"
                    ),
                    "relatedKeyVaults": vault_matches,
                }
            )

        subscription_results.append(
            result_entry
        )

    if args.json_file:
        result = build_json_result(
            sp,
            args.subscription_filter,
            subscription_results,
        )

        try:
            with open(
                args.json_file,
                "w",
                encoding="utf-8",
            ) as output_file:
                json.dump(
                    result,
                    output_file,
                    indent=2,
                    ensure_ascii=False,
                )

                output_file.write("\n")

        except OSError as exc:
            print(
                f"ERROR: Could not write JSON file: {exc}",
                file=sys.stderr,
            )
            sys.exit(1)

        print(
            f"JSON report written to: {args.json_file}"
        )


if __name__ == "__main__":
    main()