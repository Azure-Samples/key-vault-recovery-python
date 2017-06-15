# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
# This script expects that the following environment vars are set, or they can be hardcoded in key_vault_sample_config, these values
# SHOULD NOT be hardcoded in any code derived from this sample:
#
# AZURE_TENANT_ID: with your Azure Active Directory tenant id or domain
# AZURE_CLIENT_ID: with your Azure Active Directory Application Client ID
# AZURE_CLIENT_OID: with your Azure Active Directory Application Client Object ID
# AZURE_CLIENT_SECRET: with your Azure Active Directory Application Secret
# AZURE_SUBSCRIPTION_ID: with your Azure Subscription Id
#
# These are read from the environment and exposed through the KeyVaultSampleConfig class. For more information please
# see the implementation in key_vault_sample_config.py


from key_vault_sample_base import KeyVaultSampleBase
from azure.keyvault import KeyVaultId

class BackupRestoreSample(KeyVaultSampleBase):
    """
    Collection of samples using the backup and restore features of Azure Key Vault
    """
    def backup_restore_secret(self):
        """
        Creates a key vault containing a secret, then uses backup_secret and restore_secret to 
        import the secret to another key vault 
        :return: None
        """
        self.setup_sample()

        # create a key vault
        first_vault = self.create_vault()

        # add a secret to the vault
        secret_name = KeyVaultSampleBase.get_unique_name('secret')
        secret_value = 'this is a secret value to be migrated from one vault to another'

        secret = self.keyvault_data_client.set_secret(first_vault.properties.vault_uri, secret_name, secret_value)

        print(secret)

        # backup the secret
        backup = self.keyvault_data_client.backup_secret(first_vault.properties.vault_uri, secret_name)

        print(backup)

        # create a second vault
        second_vault = self.create_vault()

        # restore the secret to the new vault
        self.keyvault_data_client.restore_secret(second_vault.properties.vault_uri, backup.value)

        # get the secret from the new vault
        restored_secret = self.keyvault_data_client.get_secret(second_vault.properties.vault_uri, secret_name, KeyVaultId.version_none)

        print(restored_secret)

    def backup_restore_key(self):
        """
        Creates a key vault containing a key, then uses backup_key and restore_key to 
        import the key with matching versions to another key vault 
        :return: None
        """
        self.setup_sample()

        # create a key vault
        first_vault = self.create_vault()

        # create a key in the vault
        key_name = KeyVaultSampleBase.get_unique_name()

        key = self.keyvault_data_client.create_key(first_vault.properties.vault_uri, key_name, 'RSA')

        print(key)

        # backup the key
        backup = self.keyvault_data_client.backup_key(first_vault.properties.vault_uri, key_name)

        print(backup)

        # create a second vault
        second_vault = self.create_vault()

        # restore the key to the new vault
        self.keyvault_data_client.restore_key(second_vault.properties.vault_uri, backup.value)

        # get the secret from the new vault
        restored_key = self.keyvault_data_client.get_key(second_vault.properties.vault_uri, key_name, KeyVaultId.version_none)

        print(restored_key)


if __name__ == "__main__":
    sample = BackupRestoreSample()
    sample.run_samples()