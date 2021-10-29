# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
# This script expects that the following environment vars are set, or they can be hardcoded in key_vault_sample_config, these values
# SHOULD NOT be hardcoded in any code derived from this sample:
#
# AZURE_TENANT_ID: with your Azure Active Directory tenant id or domain
# AZURE_CLIENT_ID: with your Azure Active Directory Service Principal AppId
# AZURE_CLIENT_OID: with your Azure Active Directory Service Principle Object ID
# AZURE_CLIENT_SECRET: with your Azure Active Directory Application Key
# AZURE_SUBSCRIPTION_ID: with your Azure Subscription Id
#
# These are read from the environment and exposed through the KeyVaultSampleConfig class. For more information please
# see the implementation in key_vault_sample_config.py


from key_vault_sample_base import KeyVaultSampleBase, keyvaultsample, get_name, run_all_samples
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.certificates import CertificateClient, CertificatePolicy


class BackupRestoreSample(KeyVaultSampleBase):
    """
    A collection of samples using the backup and restore features of Azure Key Vault
    """

    @keyvaultsample
    def backup_restore_secret(self):
        """
        backs up a key vault secret and restores it to another key vault
        """
        # create a key vault
        first_vault = self.create_vault()

        # create a secret client
        credential = DefaultAzureCredential()
        first_secret_client = SecretClient(vault_url=first_vault.properties.vault_uri, credential=credential)

        # add a secret to the vault
        secret_name = get_name('secret')
        secret_value = 'this is a secret value to be migrated from one vault to another'

        secret = first_secret_client.set_secret(secret_name, secret_value)
        print('created secret {}'.format(secret.name))

        # list the secrets in the vault
        secret_properties = first_secret_client.list_properties_of_secrets()
        print("all of the secrets in the client's vault:")
        for secret_property in secret_properties:
            print(secret_property.name)

        # backup the secret
        backup = first_secret_client.backup_secret(secret_name)
        print('backed up secret {}'.format(secret_name))

        # create a second vault
        second_vault = self.create_vault()

        # create a secret client
        second_secret_client = SecretClient(vault_url=second_vault.properties.vault_uri, credential=credential)

        # restore the secret to the new vault
        restored = second_secret_client.restore_secret_backup(backup)
        print('restored secret {}'.format(restored.name))

        # list the secrets in the new vault
        secret_properties = second_secret_client.list_properties_of_secrets()
        print("all of the secrets in the new vault:")
        for secret_property in secret_properties:
            print(secret_property.name)


    @keyvaultsample
    def backup_restore_key(self):
        """
        backs up a key vault key and restores it to another key vault
        """
        # create a key vault
        first_vault = self.create_vault()

        # create a key client
        credential = DefaultAzureCredential()
        first_key_client = KeyClient(vault_url=first_vault.properties.vault_uri, credential=credential)

        # create a key in the vault
        key_name = get_name('key')
        key = first_key_client.create_key(key_name, 'RSA')
        print('created key {}'.format(key.name))

        # list the keys in the vault
        keys = first_key_client.list_properties_of_keys()
        print("keys in the first vault:")
        for key in keys:
            print(key.name)

        # backup the key
        backup = first_key_client.backup_key(key_name)
        print('backed up key {}'.format(key_name))

        # create a second vault
        second_vault = self.create_vault()

        # create a key client
        second_key_client = KeyClient(vault_url=second_vault.properties.vault_uri, credential=credential)

        # restore the key to the new vault
        restored = second_key_client.restore_key_backup(backup)
        print('restored secret {}'.format(restored.name))

        # list the keys in the new vault
        keys = second_key_client.list_properties_of_keys()
        print("keys in the second vault:")
        for key in keys:
            print(key.name)
    

    @keyvaultsample
    def backup_restore_certificate(self):
        """
        backs up a key vault certificate and restores it to another key vault
        """
        # create a key vault
        first_vault = self.create_vault()

        # create a certificate client
        credential = DefaultAzureCredential()
        first_certificate_client = CertificateClient(vault_url=first_vault.properties.vault_uri, credential=credential)

        # add a certificate to the vault
        certificate_name = get_name('certificate')

        certificate = first_certificate_client.begin_create_certificate(certificate_name, CertificatePolicy.get_default()).result()
        print('created certificate {}'.format(certificate.name))

        # list the certificates in the vault
        certificate_properties = first_certificate_client.list_properties_of_certificates()
        print("all of the certificates in the client's vault:")
        for certificate_propertie in certificate_properties:
            print(certificate_propertie.name)

        # backup the certificate
        backup = first_certificate_client.backup_certificate(certificate_name)
        print('backed up certificate {}'.format(certificate_name))

        # create a second vault
        second_vault = self.create_vault()

        # create a certificate client
        second_certificate_client = CertificateClient(vault_url=second_vault.properties.vault_uri, credential=credential)

        # restore the certificate to the new vault
        restored = second_certificate_client.restore_certificate_backup(backup)
        print('restored certificate {}'.format(restored.name))

        # list the certificates in the new vault
        secret_properties = second_certificate_client.list_properties_of_certificates()
        print("all of the certificates in the new vault:")
        for secret_propertie in secret_properties:
            print(secret_propertie.name)


if __name__ == "__main__":
    run_all_samples([BackupRestoreSample()])
