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

import time
import sys
from azure.mgmt.keyvault.models import Permissions, KeyPermissions, SecretPermissions, CertificatePermissions, \
    AccessPolicyEntry, VaultProperties, VaultCreateOrUpdateParameters, Sku
from azure.keyvault.models import KeyVaultErrorException
from key_vault_sample_base import KeyVaultSampleBase, KEY_PERMISSIONS_ALL, SECRET_PERMISSIONS_ALL, CERTIFICATE_PERMISSIONS_ALL, \
    keyvaultsample


class SoftDeleteSample(KeyVaultSampleBase):
    """
    Collection of samples using the soft delete feature of Azure Key Vault
    """
    @keyvaultsample
    def create_soft_delete_enabled_vault_sample(self):
        """
        Provides a sample for creating a key vault which has recovery enable so that the vault as well as all of its keys, 
        certificates and secrets are recoverable
        :return: a key vault which has been created with recovery enabled 
        :rtype: :class:`Vault <azure.keyvault.generated.models.Vault>`
        """
        self.setup_sample()

        vault_name = KeyVaultSampleBase.get_unique_name()

        permissions = Permissions()
        permissions.keys = KEY_PERMISSIONS_ALL
        permissions.secrets = SECRET_PERMISSIONS_ALL
        permissions.certificates = CERTIFICATE_PERMISSIONS_ALL

        policy = AccessPolicyEntry(self.config.tenant_id, self.config.client_oid, permissions)

        properties = VaultProperties(self.config.tenant_id, Sku(name='standard'), access_policies=[policy])

        parameters = VaultCreateOrUpdateParameters(self.config.location, properties)
        parameters.properties.enabled_for_deployment = True
        parameters.properties.enabled_for_disk_encryption = True
        parameters.properties.enabled_for_template_deployment = True

        # this vault property controls whether recovery functionality is available on the vault itself as well as
        # all keys, certificates and secrets in the vault as well
        # NOTE: This value should only None or True, setting the value to false will cause a service validation error
        #       once soft delete has been enabled on the vault it cannot be disabled
        parameters.properties.enable_soft_delete = True

        print('Creating vault with soft delete enabled: {}'.format(vault_name))

        # create the vault
        vault = self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_name, vault_name, parameters)

        # wait for vault DNS entry to be created
        # see issue: https://github.com/Azure/azure-sdk-for-python/issues/1172
        self._poll_for_vault_connection(vault.properties.vault_uri)

        self._print_obj(vault)
        return vault

    @keyvaultsample
    def enable_soft_delete_on_existing_vault_sample(self):
        """        
        Provides sample code for enabling soft delete on an existing vault
        :return: None 
        """
        self.setup_sample()

        # create a vault without soft delete enabled
        vault = self.create_vault()

        # this vault property controls whether recovery functionality is available on the vault itself as well as
        # all keys, certificates and secrets in the vault as well
        # NOTE: This value should only None or True, setting the value to false will cause a service validation error
        #       once soft delete has been enabled on the vault it cannot be disabled
        vault.properties.enable_soft_delete = True

        # update the vault to enable soft delete 
        self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_name,
                                                          vault.name,
                                                          VaultCreateOrUpdateParameters(vault.location, vault.properties))

    def _enable_soft_delete_for_vault(self, vault):
        vault.properties.enable_soft_delete = True

        print('Enabling soft delete on vault: {}'.format(vault.name))
        # update the vault to enable soft delete
        self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_name,
                                                          vault.name,
                                                          VaultCreateOrUpdateParameters(vault.location, vault.properties))

    @keyvaultsample
    def deleted_vault_sample(self):
        """
        Provides a sample code for enumerating, retrieving, recovering and purging deleted key vaults
        :return: None 
        """
        self.setup_sample()

        # create vaults enabling the soft delete feature on each
        vault_to_recover = self.create_vault()
        self._enable_soft_delete_for_vault(vault_to_recover)
        vault_to_purge = self.create_vault()
        self._enable_soft_delete_for_vault(vault_to_purge)

        # delete the vaults
        print('Deleting vault: {}'.format(vault_to_recover.name))
        self.keyvault_mgmt_client.vaults.delete(self.config.group_name, vault_to_recover.name)
        self._wait_on_delete_completed(None, 'vault', vault_to_recover.name)

        print('Deleting vault: {}'.format(vault_to_recover.name))
        self.keyvault_mgmt_client.vaults.delete(self.config.group_name, vault_to_purge.name)
        self._wait_on_delete_completed(None, 'vault', vault_to_purge.name)

        # list the deleted vaults
        print('Deleted Vaults: ')
        deleted_vaults = self.keyvault_mgmt_client.vaults.list_deleted()
        self._print_obj(deleted_vaults)

        # get the details of a specific deleted vault
        print('Getting deleted vault info for vault: {}'.format(vault_to_recover.name))
        deleted_info = self.keyvault_mgmt_client.vaults.get_deleted(vault_to_recover.name, vault_to_recover.location)
        print(deleted_info)

        # to restore the vault simply supply the group, location, and name and set the 'create_mode' vault property to 'recover'
        # setting this property will cause other properties passed to create_or_update to be ignored and will simply
        # restore the vault in the state it was when it was deleted
        print('Recovering vault: {}'.format(vault_to_recover.name))
        recovery_properties = VaultProperties(tenant_id=self.config.tenant_id, Sku='', access_policies=[], create_mode='recover')
        recovery_parameters = VaultCreateOrUpdateParameters(deleted_info.location, recovery_properties)
        recovered = self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_name, deleted_info.name, recovery_parameters)
        self._print_obj(recovered)

        # list the deleted vaults again only the vault we intend to purge is still deleted
        print('Deleted Vaults: ')
        deleted_vaults = self.keyvault_mgmt_client.vaults.list_deleted()
        self._print_obj(deleted_vaults)

        # purge the last deleted vault
        print('Purging vault: {}'.format(vault_to_recover.name))
        self.keyvault_mgmt_client.vaults.purge_deleted(vault_to_purge.name, vault_to_purge.location)

        # verify no deleted vaults remain
        print('Deleted Vaults: ')
        deleted_vaults = self.keyvault_mgmt_client.list_deleted()
        self._print_obj(deleted_vaults)

    @keyvaultsample
    def deleted_secret_sample(self):
        """
        Provides a sample code for enumerating, retrieving, recovering and purging deleted secrets from a key vault
        :return: None 
        """
        self.setup_sample()

        # create a vault enabling the soft delete feature
        vault = self.create_vault()
        self._enable_soft_delete_for_vault(vault)

        # create secrets in the vault
        secret_to_recover = self.get_unique_name()
        secret_to_purge = self.get_unique_name()

        print('Creating Secret: {}'.format(secret_to_recover))
        secret = self.keyvault_data_client.set_secret(vault.properties.vault_uri, secret_to_recover, "secret to restore")
        self._print_obj(secret)

        print('Creating Secret: {}'.format(secret_to_recover))
        secret = self.keyvault_data_client.set_secret(vault.properties.vault_uri, secret_to_purge, "secret to purge")
        self._print_obj(secret)

        # list the vaults secrets
        print('Secrets: ')
        secrets = self.keyvault_data_client.get_secrets(vault.properties.vault_uri)
        self._print_obj(secrets)

        # delete the secrets
        print('Deleting secret: {}'.format(secret_to_recover))
        self.keyvault_data_client.delete_secret(vault.properties.vault_uri, secret_to_recover)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'secret', secret_to_recover)

        print('Deleting secret: {}'.format(secret_to_purge))
        self.keyvault_data_client.delete_secret(vault.properties.vault_uri, secret_to_purge)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'secret', secret_to_purge)

        # list the deleted secrets
        print('Secrets: ')
        deleted_secrets = self.keyvault_data_client.get_deleted_secrets(vault.properties.vault_uri)
        self._print_obj(deleted_secrets)

        # recover a deleted secret
        print('Recovering secret: {}'.format(secret_to_recover))
        self.keyvault_data_client.recover_deleted_secret(vault.properties.vault_uri, secret_to_recover)

        # purge a deleted secret
        print('Purging secret: {}'.format(secret_to_purge))
        self.keyvault_data_client.purge_deleted_secret(vault.properties.vault_uri, secret_to_purge)

        # list the vaults secrets
        print('Secrets: ')
        secrets = self.keyvault_data_client.get_secrets(vault.properties.vault_uri)
        self._print_obj(secrets)

    @keyvaultsample
    def deleted_key_sample(self):
        """
        Provides a sample code for enumerating, retrieving, recovering and purging deleted keys from a key vault
        :return: None 
        """
        self.setup_sample()

        # create a vault enabling the soft delete feature
        vault = self.create_vault()
        self._enable_soft_delete_for_vault(vault)

        # create keys in the vault
        key_to_recover = self.get_unique_name()
        key_to_purge = self.get_unique_name()
        self.keyvault_data_client.create_key(vault.properties.vault_uri, key_to_recover, 'RSA')
        self.keyvault_data_client.create_key(vault.properties.vault_uri, key_to_purge, 'RSA')
        self._wait_on_delete_completed(vault.properties.vault_uri, 'key', key_to_recover)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'key', key_to_purge)

        # list the vaults keys
        keys = self.keyvault_data_client.get_keys(vault.properties.vault_uri)
        print(keys)

        # delete the keys
        self.keyvault_data_client.delete_key(vault.properties.vault_uri, key_to_recover)
        self.keyvault_data_client.delete_key(vault.properties.vault_uri, key_to_purge)

        # list the deleted keys
        deleted_keys = self.keyvault_data_client.get_deleted_keys(vault.properties.vault_uri)
        print(deleted_keys)

        # recover a deleted key
        self.keyvault_data_client.recover_deleted_key(vault.properties.vault_uri, key_to_recover)

        # purge a deleted key
        self.keyvault_data_client.purge_deleted_key(vault.properties.vault_uri, key_to_purge)

        # list the vaults key
        keys = self.keyvault_data_client.get_keys(vault.properties.vault_uri)
        print(keys)

    @keyvaultsample
    def deleted_certificate_sample(self):
        """
        Provides a sample code for enumerating, retrieving, recovering and purging deleted certificates from a key vault
        :return: None 
        """
        self.setup_sample()

        # create a vault enabling the soft delete feature
        vault = self.create_vault()
        self._enable_soft_delete_for_vault(vault)

        # create certificates in the vault
        cert_to_recover = self.get_unique_name()
        cert_to_purge = self.get_unique_name()
        self.keyvault_data_client.create_certificate(vault.properties.vault_uri, cert_to_recover)
        self.keyvault_data_client.create_certificate(vault.properties.vault_uri, cert_to_purge)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'certificate', cert_to_recover)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'certificate', cert_to_purge)

        # list the vaults certificates
        certs = self.keyvault_data_client.get_certificates(vault.properties.vault_uri)
        print(certs)

        # delete the certificates
        self.keyvault_data_client.delete_certificate(vault.properties.vault_uri, cert_to_recover)
        self.keyvault_data_client.delete_certificate(vault.properties.vault_uri, cert_to_purge)

        # list the deleted certificates
        deleted_certs = self.keyvault_data_client.get_deleted_certificates(vault.properties.vault_uri)
        print(deleted_certs)

        # recover a deleted certificate
        self.keyvault_data_client.recover_deleted_certificate(vault.properties.vault_uri, cert_to_recover)

        # purge a deleted certificate
        self.keyvault_data_client.purge_deleted_certificate(vault.properties.vault_uri, cert_to_purge)

        # list the vaults certificate
        keys = self.keyvault_data_client.get_certificates(vault.properties.vault_uri)
        print(keys)
        
    def _wait_on_delete_completed(self, vault_uri, entity_type, entity_name):
        get_deleted_func = None
        
        if entity_type == 'secret':
            get_deleted_func = self.keyvault_data_client.get_deleted_secret
            args = (vault_uri, entity_name)
        elif entity_type == 'key':
            get_deleted_func = self.keyvault_data_client.get_deleted_key
            args = (vault_uri, entity_name)
        elif entity_type == 'certificate':
            get_deleted_func = self.keyvault_data_client.get_deleted_certificate
            args = (vault_uri, entity_name)
        else:  # entity_type == 'vault'
            get_deleted_func = self.keyvault_mgmt_client.vaults.get_deleted
            args = (entity_name, self.config.location)
        self._poll_while_404(get_deleted_func, args)
        
    def _poll_while_404(self, func, args=(), retry_wait=10, max_retries=10):
        for x in range(max_retries):
            try:
                return func(*args[0:]) 
            except KeyVaultErrorException as e:
                if not e.response.status_code == 404:
                    raise e
                time.sleep(retry_wait)


if __name__ == "__main__":
    sample = SoftDeleteSample()
    sample.run_samples(sys.argv[1:])

