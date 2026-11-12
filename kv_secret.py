#!/usr/bin/env python3

import argparse
import sys
from typing import Optional

from azure.core.exceptions import HttpResponseError
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient


# Tenant used when --tenant-id is not given. Fill in your tenant ID here.
DEFAULT_TENANT_ID = ""

PREVIEW_LENGTH = 10
PREVIEW_MAX_LENGTH = 100

# Characters of the client secret shown in the output header.
CLIENT_SECRET_VISIBLE_LENGTH = 3


def parse_credentials(value: str) -> tuple[str, str]:
    """Split 'client_id:secret' into its two parts."""

    # Split on the first colon only: a client ID never contains
    # one, but a client secret can.
    client_id, separator, client_secret = value.partition(":")

    if not separator or not client_id or not client_secret:
        raise argparse.ArgumentTypeError(
            "expected the form client_id:secret"
        )

    return client_id.strip(), client_secret


def mask(value: str, visible_length: int) -> str:
    """Keep the first characters of a value and replace the rest with '*'."""

    return (
        value[:visible_length]
        + "*" * max(len(value) - visible_length, 0)
    )


def format_value(
    value: Optional[str],
    preview: bool,
) -> str:
    """Return the secret value, or a masked preview of it."""

    if value is None:
        return ""

    if not preview:
        return value

    masked = mask(value, PREVIEW_LENGTH)

    if len(masked) > PREVIEW_MAX_LENGTH:
        return masked[:PREVIEW_MAX_LENGTH] + "..."

    return masked


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "List the secrets in an Azure Key Vault and print "
            "their values, signing in as a Service Principal."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "name",
        help="Key Vault name, as in <name>.vault.azure.net.",
    )

    parser.add_argument(
        "--credentials",
        required=True,
        type=parse_credentials,
        metavar="CLIENT_ID:SECRET",
        help=(
            "Service Principal client ID and client secret, "
            "separated by a colon."
        ),
    )

    parser.add_argument(
        "--tenant-id",
        default=DEFAULT_TENANT_ID,
        help=(
            "Microsoft Entra tenant ID of the Service Principal. "
            "Defaults to DEFAULT_TENANT_ID in this script."
        ),
    )

    parser.add_argument(
        "--name-filter",
        help=(
            "Only show secrets whose name contains this text. "
            "The match ignores case. Shows all secrets if omitted."
        ),
    )

    parser.add_argument(
        "--preview",
        action="store_true",
        help=(
            f"Show the first {PREVIEW_LENGTH} characters of each "
            "secret value and replace the rest with '*'. Values "
            f"longer than {PREVIEW_MAX_LENGTH} characters are cut "
            "off and end with '...'."
        ),
    )

    args = parser.parse_args()

    if not args.tenant_id:
        parser.error(
            "--tenant-id is required "
            "when DEFAULT_TENANT_ID in the script is empty"
        )

    client_id, client_secret = args.credentials

    credential = ClientSecretCredential(
        tenant_id=args.tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        additionally_allowed_tenants=["*"],
    )

    client = SecretClient(
        vault_url=f"https://{args.name}.vault.azure.net/",
        credential=credential,
    )

    search_value = (
        args.name_filter.casefold()
        if args.name_filter
        else None
    )

    print(f"Key Vault:     {args.name}")
    print(f"Name filter:   {args.name_filter or '(none, all secrets)'}")
    print(f"Tenant ID:     {args.tenant_id}")
    print(f"Client ID:     {client_id}")
    print(
        "Client secret: "
        f"{mask(client_secret, CLIENT_SECRET_VISIBLE_LENGTH)}"
    )
    print()

    shown = 0

    try:
        for secret_property in client.list_properties_of_secrets():
            secret_name = secret_property.name

            if (
                search_value
                and search_value not in secret_name.casefold()
            ):
                continue

            if not secret_property.enabled:
                print(f"{secret_name} <disabled>")
                shown += 1
                continue

            try:
                secret = client.get_secret(secret_name)
            except HttpResponseError as exc:
                print(
                    f"WARNING: Could not read secret "
                    f"'{secret_name}': {exc.message}",
                    file=sys.stderr,
                )
                continue

            print(
                secret_name,
                format_value(secret.value, args.preview),
            )
            shown += 1

    except HttpResponseError as exc:
        print(
            f"ERROR: Could not list secrets in '{args.name}': "
            f"{exc.message}",
            file=sys.stderr,
        )
        sys.exit(1)

    if shown == 0 and search_value:
        print(
            f"No secrets were found whose name contains "
            f"'{args.name_filter}'."
        )


if __name__ == "__main__":
    main()
