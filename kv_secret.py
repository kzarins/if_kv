from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
import argparse

parser = argparse.ArgumentParser(description="KeyVault permission check",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("name", help="KeyVault <name>.vault.azure.net")
args = vars(parser.parse_args())

vault = args["name"]

credential = ClientSecretCredential(
    tenant_id="",
    client_id="",
    client_secret="",
    additionally_allowed_tenants=['*'],
)

client = SecretClient(vault_url="https://" + vault + ".vault.azure.net/", credential=credential)

secret_properties = client.list_properties_of_secrets()

for secret_property in secret_properties:
    if ("curity" in secret_property.name): 
        print(secret_property.name, client.get_secret(secret_property.name).value)

    print(secret_property.name, client.get_secret(secret_property.name).value)