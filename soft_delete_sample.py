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

from azure.mgmt.keyvault.models import Permissions, KeyPermissions, SecretPermissions, CertificatePermissions, \
    AccessPolicyEntry, VaultProperties, VaultCreateOrUpdateParameters, Sku
from azure.keyvault.models import KeyVaultErrorException
from key_vault_sample_base import KeyVaultSampleBase, ALL_KEY_PERMISSIONS, ALL_SECRET_PERMISSIONS, ALL_CERT_PERMISSIONS


class KeyVaultRecoverySample(KeyVaultSampleBase):
    """
    Collection of samples using the soft delete feature of Azure Key Vault
    """
    def __init__(self):
        super(KeyVaultSampleBase, self).__init__()

    def run_samples(self):
        """
        Runs all key vault recover samples
        :return: None
        """
        self.create_soft_delete_enabled_vault_sample()
        self.enable_soft_delete_on_existing_vault_sample()
        self.deleted_vault_sample()
        self.deleted_secret_sample()
        self.deleted_key_sample()
        self.deleted_certificate_sample()

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
        permissions.keys = ALL_KEY_PERMISSIONS
        permissions.secrets = ALL_SECRET_PERMISSIONS
        permissions.certificates = ALL_CERT_PERMISSIONS

        policy = AccessPolicyEntry(self.config.tenant_id, self.config.client_oid, permissions)

        properties = VaultProperties(self.config.tenant_id, Sku(name='standard'), policies=[policy])

        parameters = VaultCreateOrUpdateParameters(self.config.location, properties)
        parameters.properties.enabled_for_deployment = True
        parameters.properties.enabled_for_disk_encryption = True
        parameters.properties.enabled_for_template_deployment = True

        # this vault property controls whether recovery functionality is available on the vault itself as well as
        # all keys, certificates and secrets in the vault as well
        # NOTE: This value should only None or True, setting the value to false will cause a service validation error
        #       once soft delete has been enabled on the vault it cannot be disabled
        parameters.properties.enable_soft_delete = True

        # create the vault
        vault = self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_name, vault_name, parameters)

        print(vault)
        return vault

    def enable_soft_delete_on_existing_vault_sample(self):
        """        
        Provides sample code for enableling soft delete on an existing vault
        :return: None 
        """
        self.setup_sample()

        # create a vault without soft delete enabled
        vault = self.create_vault()

        # this vault property controls whether recovery functionality is available on the vault itself as well as
        # all keys, certificates and secrets in the vault as well
        # NOTE: This value should only None or True, setting the value to false will cause a service validation error
        #       once soft delete has been enabled on the vault it cannot be disabled
        vault.properties.enable_for_soft_delete = True
        
        # update the vault to enable soft delete 
        self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_name, vault_name, vault)

    def deleted_vault_sample(self):
        """
        Provides a sample code for enumerating, retrieving, recovering and purging deleted key vaults
        :return: None 
        """
        self.setup_sample()

        # create vaults enabling the soft delete feature on each
        vault_to_recover = self.create_soft_delete_enabled_vault_sample()
        vault_to_purge = self.create_soft_delete_enabled_vault_sample()

        # delete the vaults
        self.keyvault_mgmt_client.vaults.delete(self.config.group_name, vault_to_recover.name)
        self.keyvault_mgmt_client.vaults.delete(self.config.group_name, vault_to_purge.name)

        # list the deleted vaults
        deleted_vaults = self.keyvault_mgmt_client.list_deleted()
        print(deleted_vaults)

        # get the details of a specific deleted vault
        deleted_info = self.keyvault_mgmt_client.get_deleted(vault_to_recover.name, vault_to_recover.location)
        print(deleted_info)

        # to restore the vault simply supply the group, location, and name and set the 'create_mode' vault property to 'recover'
        # setting this property will cause other properties passed to create_or_update to be ignored and will simply
        # restore the vault in the state it was when it was deleted
        recovery_properties = VaultProperties(location=vault_to_recover.location, '', access_policies=[], create_mode='recover')
        recovery_parameters = VaultCreateOrUpdateParameters(deleted_info.location, recovery_properties)
        self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_name, deleted_info.name, recovery_parameters)

        # list the deleted vaults again only the vault we intend to purge is still deleted
        deleted_vaults = self.keyvault_mgmt_client.list_deleted()
        print(deleted_vaults)

        # purge the last deleted vault
        self.keyvault_mgmt_client.vaults.purge_deleted(vault_to_purge.name, vault_to_purge.location)

        # verify no deleted vaults remain
        deleted_vaults = self.keyvault_mgmt_client.list_deleted()
        print(deleted_vaults)

    def deleted_secret_sample(self):
        """
        Provides a sample code for enumerating, retrieving, recovering and purging deleted secrets from a key vault
        :return: None 
        """
        self.setup_sample()

        # create a vault enabling the soft delete feature
        vault = self.create_soft_delete_enabled_vault_sample()

        # create secrets in the vault
        secret_to_recover = self.get_unique_name()
        secret_to_purge = self.get_unique_name()
        self.keyvault_data_client.set_secret(vault.properties.vault_uri, secret_to_recover, "secret to restore")
        self.keyvault_data_client.set_secret(vault.properties.vault_uri, secret_to_purge, "secret to purge")

        # list the vaults secrets
        secrets = self.keyvault_data_client.get_secrets(vault.properties.vault_uri)
        print(secrets)

        # delete the secrets
        self.keyvault_data_client.delete_secret(vault.properties.vault_uri, secret_to_recover)
        self.keyvault_data_client.delete_secret(vault.properties.vault_uri, secret_to_purge)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'secret', secret_to_recover)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'secret', secret_to_purge)

        # list the deleted secrets
        deleted_secrets = self.keyvault_data_client.get_deleted_secrets(vault.properties.vault_uri)
        print(deleted_secrets)

        # recover a deleted secret
        self.keyvault_data_client.recover_deleted_secret(vault.properties.vault_uri, secret_to_recover)

        # purge a deleted secret
        self.keyvault_data_client.purge_deleted_secret(vault.properties.vault_uri, secret_to_purge)

        # list the vaults secrets
        secrets = self.keyvault_data_client.get_secrets(vault.properties.vault_uri)
        print(secrets)

    def deleted_key_sample(self):
        """
        Provides a sample code for enumerating, retrieving, recovering and purging deleted keys from a key vault
        :return: None 
        """
        self.setup_sample()

        # create a vault enabling the soft delete feature
        vault = self.create_soft_delete_enabled_vault_sample()

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

    def deleted_certificate_sample(self):
        """
        Provides a sample code for enumerating, retrieving, recovering and purging deleted certificates from a key vault
        :return: None 
        """
        self.setup_sample()

        # create a vault enabling the soft delete feature
        vault = self.create_soft_delete_enabled_vault_sample()

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
        elif entity_type == 'key':
            get_deleted_func = self.keyvault_data_client.get_deleted_key
        else: # entity_type == 'certificate':
            get_deleted_func = self.keyvault_data_client.get_deleted_certificate

        self._poll_while_404(get_deleted_func, args=(vault_uri, entity_name))
        
    def _poll_while_404(self, func, args=(), retry_wait=10, max_retries=10):
        for x in range(max_retries):
            try:
                return func(*args[0:]) 
            except KeyVaultErrorException e:
                if not e.response.status_code == 404:
                    raise e


if __name__ == "__main__":
    sample = KeyVaultRecoverySample()
    sample.run_samples()

