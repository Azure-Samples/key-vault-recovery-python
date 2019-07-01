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

        # add a secret to the vault
        secret_name = get_name('secret')
        secret_value = 'this is a secret value to be migrated from one vault to another'

        secret = self.keyvault_data_client.set_secret(
            first_vault.properties.vault_uri, secret_name, secret_value)
        print('created secret {}\n{}'.format(
            secret_name, self._serialize(secret)))

        # list the secrets in the vault
        secrets = self.keyvault_data_client.get_secrets(
            first_vault.properties.vault_uri)
        print('vault {} secrets:\n{}'.format(
            first_vault.name, self._serialize(secrets)))

        # backup the secret
        backup = self.keyvault_data_client.backup_secret(
            first_vault.properties.vault_uri, secret_name)
        print('backed up secret {} value: {}'.format(secret_name, backup))

        # create a second vault
        second_vault = self.create_vault()

        # restore the secret to the new vault
        restored = self.keyvault_data_client.restore_secret(
            second_vault.properties.vault_uri, backup.value)
        print('restored secret {}\n{}'.format(
            secret_name, self._serialize(restored)))

        # list the secrets in the new vault
        secrets = self.keyvault_data_client.get_secrets(
            second_vault.properties.vault_uri)
        print('vault {} secrets:\n{}'.format(
            second_vault.name, self._serialize(secrets)))

    @keyvaultsample
    def backup_restore_key(self):
        """
        backs up a key vault key and restores it to another key vault
        """
        # create a key vault
        first_vault = self.create_vault()

        # create a key in the vault
        key_name = get_name('key')
        key = self.keyvault_data_client.create_key(
            first_vault.properties.vault_uri, key_name, 'RSA')
        print('created key {}\n{}'.format(key_name, self._serialize(key)))

        # list the keys in the vault
        keys = self.keyvault_data_client.get_keys(
            first_vault.properties.vault_uri)
        print('vault {} secrets:\n{}'.format(
            first_vault.name, self._serialize(keys)))

        # backup the key
        backup = self.keyvault_data_client.backup_key(
            first_vault.properties.vault_uri, key_name)
        print('backed up key {} value: {}'.format(key_name, backup))

        # create a second vault
        second_vault = self.create_vault()

        # restore the key to the new vault
        restored = self.keyvault_data_client.restore_key(
            second_vault.properties.vault_uri, backup.value)
        print('restored secret {}\n{}'.format(
            key_name, self._serialize(restored)))

        # list the keys in the new vault
        keys = self.keyvault_data_client.get_keys(
            second_vault.properties.vault_uri)
        print('vault {} secrets:\n{}'.format(
            second_vault.name, self._serialize(keys)))


if __name__ == "__main__":
    run_all_samples([BackupRestoreSample()])
