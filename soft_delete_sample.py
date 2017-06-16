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
from azure.mgmt.keyvault.models import Permissions, KeyPermissions, SecretPermissions, CertificatePermissions, \
    AccessPolicyEntry, VaultProperties, VaultCreateOrUpdateParameters, Sku, SkuName
from azure.keyvault.models import KeyVaultErrorException
from azure.keyvault import KeyVaultId
from key_vault_sample_base import KeyVaultSampleBase, KEY_PERMISSIONS_ALL, SECRET_PERMISSIONS_ALL, CERTIFICATE_PERMISSIONS_ALL, \
    keyvaultsample, get_name, run_all_samples


class SoftDeleteSample(KeyVaultSampleBase):
    """
    A collection of samples using the soft delete feature of Azure Key Vault
    """
    @keyvaultsample
    def create_soft_delete_enabled_vault(self):
        """
        creates a key vault which has soft delete enabled so that the vault as well as all of its keys, 
        certificates and secrets are recoverable
        """
        vault_name = get_name('vault')

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

        print('creating soft delete enabled vault: {}'.format(vault_name))

        # create the vault
        vault = self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_name, vault_name, parameters)

        # wait for vault DNS entry to be created
        # see issue: https://github.com/Azure/azure-sdk-for-python/issues/1172
        self._poll_for_vault_connection(vault.properties.vault_uri)

        print('vault {} created enable_soft_delete={}'.format(vault.name, vault.properties.enable_soft_delete))


    @keyvaultsample
    def enable_soft_delete_on_existing_vault(self):
        """        
        enables soft delete on an existing vault
        """
        # create a vault without soft delete enabled
        vault = self.create_vault()

        # this vault property controls whether recovery functionality is available on the vault itself as well as
        # all keys, certificates and secrets in the vault as well
        # NOTE: This value should only None or True, setting the value to false will cause a service validation error
        #       once soft delete has been enabled on the vault it cannot be disabled
        vault.properties.enable_soft_delete = True

        # update the vault to enable soft delete 
        vault = self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_name,
                                                          vault.name,
                                                          VaultCreateOrUpdateParameters(vault.location, vault.properties))

        print('updated vault {} enable_soft_delete={}'.format(vault.name, vault.properties.enable_soft_delete))

    def _enable_soft_delete_for_vault(self, vault):
        vault.properties.enable_soft_delete = True

        # update the vault to enable soft delete
        self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_name,
                                                          vault.name,
                                                          VaultCreateOrUpdateParameters(vault.location, vault.properties))

        print('updated vault {} enable_soft_delete={}'.format(vault.name, vault.properties.enable_soft_delete))


    @keyvaultsample
    def deleted_vault_recovery(self):
        """
        a sample of enumerating, retrieving, recovering and purging deleted key vaults
        """
        # create vaults enabling the soft delete feature on each
        vault_to_recover = self.create_vault()
        self._enable_soft_delete_for_vault(vault_to_recover)
        vault_to_purge = self.create_vault()
        self._enable_soft_delete_for_vault(vault_to_purge)

        print('created vaults {} and {}'.format(vault_to_recover.name, vault_to_purge.name))

        # delete the vaults
        self.keyvault_mgmt_client.vaults.delete(self.config.group_name, vault_to_recover.name)
        self._wait_on_delete_completed(None, 'vault', vault_to_recover.name)
        print('Deleted vault: {}'.format(vault_to_recover.name))

        self.keyvault_mgmt_client.vaults.delete(self.config.group_name, vault_to_purge.name)
        self._wait_on_delete_completed(None, 'vault', vault_to_purge.name)
        print('Deleted vault: {}'.format(vault_to_purge.name))

        # list the deleted vaults
        deleted_vaults = self.keyvault_mgmt_client.vaults.list_deleted()
        print('Deleted Vaults: \n{}'.format(self._serialize(deleted_vaults)))

        # get the details of a specific deleted vault
        deleted_info = self.keyvault_mgmt_client.vaults.get_deleted(vault_to_recover.name, vault_to_recover.location)
        print('Deleted vault info for vault: {}\n{}'.format(vault_to_recover.name, deleted_info))

        # to restore the vault simply supply the group, location, and name and set the 'create_mode' vault property to 'recover'
        # setting this property will cause other properties passed to create_or_update to be ignored and will simply
        # restore the vault in the state it was when it was deleted
        recovery_properties = VaultProperties(tenant_id=self.config.tenant_id, sku=Sku(SkuName.standard.name), access_policies=[], create_mode='recover')
        recovery_parameters = VaultCreateOrUpdateParameters(deleted_info.properties.location, recovery_properties)
        recovered = self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_name, deleted_info.name, recovery_parameters)
        print('Recovered vault: {}'.format(recovered.name))

        # list the deleted vaults again only the vault we intend to purge is still deleted
        deleted_vaults = self.keyvault_mgmt_client.vaults.list_deleted()
        print('Deleted Vaults: \n{}'.format(self._serialize(deleted_vaults)))

        # purge the last deleted vault
        self.keyvault_mgmt_client.vaults.purge_deleted(vault_to_purge.name, vault_to_purge.location)
        print('Purged vault: {}'.format(vault_to_recover.name))

        # verify no deleted vaults remain
        deleted_vaults = self.keyvault_mgmt_client.vaults.list_deleted()
        print('Deleted Vaults: \n{}'.format(self._serialize(deleted_vaults)))

    @keyvaultsample
    def deleted_secret_recovery(self):
        """
        a sample of enumerating, retrieving, recovering and purging deleted secrets from a key vault
        """
        # create a vault enabling the soft delete feature
        vault = self.create_vault()
        self._enable_soft_delete_for_vault(vault)

        # create secrets in the vault
        secret_to_recover = get_name('secret')
        secret_to_purge = get_name('secret')

        secret = self.keyvault_data_client.set_secret(vault.properties.vault_uri, secret_to_recover, "secret to restore")
        print('created secret {}\n{}'.format(secret_to_recover, self._serialize(secret)))

        secret = self.keyvault_data_client.set_secret(vault.properties.vault_uri, secret_to_purge, "secret to purge")
        print('created secret {}\n{}'.format(secret_to_purge, self._serialize(secret)))

        # list the vault secrets
        secrets = self.keyvault_data_client.get_secrets(vault.properties.vault_uri)
        print('secrets: \n{}'.format(self._serialize(secrets)))

        # delete the secrets
        deleted_secret = self.keyvault_data_client.delete_secret(vault.properties.vault_uri, secret_to_recover)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'secret', secret_to_recover)
        print('deleted secret {}\n{}'.format(secret_to_recover, self._serialize(deleted_secret)))

        deleted_secret = self.keyvault_data_client.delete_secret(vault.properties.vault_uri, secret_to_purge)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'secret', secret_to_purge)
        print('deleted secret {}\n{}'.format(secret_to_purge, self._serialize(deleted_secret)))

        # list the deleted secrets
        deleted_secrets = self.keyvault_data_client.get_deleted_secrets(vault.properties.vault_uri)
        print('deleted secrets: \n{}'.format(self._serialize(deleted_secrets)))

        # recover a deleted secret
        secret = self.keyvault_data_client.recover_deleted_secret(vault.properties.vault_uri, secret_to_recover)
        self._wait_on_recover_completed(vault.properties.vault_uri, 'secret', secret_to_recover)
        print('recovered secret {}\n{}'.format(secret_to_recover, self._serialize(secret)))

        # purge a deleted secret
        self.keyvault_data_client.purge_deleted_secret(vault.properties.vault_uri, secret_to_purge)
        print('purged secret {}'.format(secret_to_purge))

        # list the vault secrets
        secrets = self.keyvault_data_client.get_secrets(vault.properties.vault_uri)
        print('secrets: \n{}'.format(self._serialize(secrets)))


    @keyvaultsample
    def deleted_key_recovery(self):
        """
        a sample of enumerating, retrieving, recovering and purging deleted keys from a key vault
        """
        # create a vault enabling the soft delete feature
        vault = self.create_vault()
        self._enable_soft_delete_for_vault(vault)

        # create keys in the vault
        key_to_recover = get_name('key')
        key_to_purge = get_name('key')

        key = self.keyvault_data_client.create_key(vault.properties.vault_uri, key_to_recover, 'RSA')
        print('created key {}\n{}'.format(key_to_recover, self._serialize(key)))

        key = self.keyvault_data_client.create_key(vault.properties.vault_uri, key_to_purge, 'RSA')
        print('created key {}\n{}'.format(key_to_purge, self._serialize(key)))

        # list the vault keys
        keys = self.keyvault_data_client.get_keys(vault.properties.vault_uri)
        print('keys: \n{}'.format(self._serialize(keys)))

        # delete the keys
        deleted_key = self.keyvault_data_client.delete_key(vault.properties.vault_uri, key_to_recover)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'key', key_to_recover)
        print('deleted key {}\n{}'.format(key_to_recover, self._serialize(deleted_key)))

        deleted_key = self.keyvault_data_client.delete_key(vault.properties.vault_uri, key_to_purge)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'key', key_to_purge)
        print('deleted key {}\n{}'.format(key_to_purge, self._serialize(deleted_key)))

        # list the deleted keys
        deleted_keys = self.keyvault_data_client.get_deleted_keys(vault.properties.vault_uri)
        print('deleted keys: \n{}'.format(self._serialize(deleted_keys)))

        # recover a deleted key
        key = self.keyvault_data_client.recover_deleted_key(vault.properties.vault_uri, key_to_recover)
        self._wait_on_recover_completed(vault.properties.vault_uri, 'key', key_to_recover)
        print('recovered key {}\n{}'.format(key_to_recover, self._serialize(key)))

        # purge a deleted key
        self.keyvault_data_client.purge_deleted_key(vault.properties.vault_uri, key_to_purge)
        print('purged key {}'.format(key_to_purge))

        # list the vaults key
        keys = self.keyvault_data_client.get_keys(vault.properties.vault_uri)
        print('keys: \n{}'.format(self._serialize(keys)))

    @keyvaultsample
    def deleted_certificate_recovery(self):
        """
        a sample of enumerating, retrieving, recovering and purging deleted certificates from a key vault 
        """
        # create a vault enabling the soft delete feature
        vault = self.create_vault()
        self._enable_soft_delete_for_vault(vault)

        # create certificates in the vault
        cert_to_recover = get_name('cert')
        cert_to_purge = get_name('cert')

        cert = self.keyvault_data_client.create_certificate(vault.properties.vault_uri, cert_to_recover)
        print('created certificate {}\n{}'.format(cert_to_recover, self._serialize(cert)))

        cert = self.keyvault_data_client.create_certificate(vault.properties.vault_uri, cert_to_purge)
        print('created certificate {}\n{}'.format(cert_to_purge, self._serialize(cert)))

        # list the vaults certificates
        certs = self.keyvault_data_client.get_certificates(vault.properties.vault_uri)
        print('certificates: \n{}'.format(self._serialize(certs)))

        # delete the certificates
        deleted_cert = self.keyvault_data_client.delete_certificate(vault.properties.vault_uri, cert_to_recover)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'certificate', cert_to_recover)
        print('deleted certificate {}\n{}'.format(cert_to_recover, self._serialize(deleted_cert)))

        deleted_cert = self.keyvault_data_client.delete_certificate(vault.properties.vault_uri, cert_to_purge)
        self._wait_on_delete_completed(vault.properties.vault_uri, 'certificate', cert_to_purge)
        print('deleted certificate {}\n{}'.format(cert_to_purge, self._serialize(deleted_cert)))

        # list the deleted certificates
        deleted_certs = self.keyvault_data_client.get_deleted_certificates(vault.properties.vault_uri)
        print('deleted certificates: \n{}'.format(self._serialize(deleted_certs)))

        # recover a deleted certificate
        cert = self.keyvault_data_client.recover_deleted_certificate(vault.properties.vault_uri, cert_to_recover)
        self._wait_on_recover_completed(vault.properties.vault_uri, 'key', cert_to_recover)
        print('recovered certificate {}\n{}'.format(cert_to_recover, self._serialize(cert)))

        # purge a deleted certificate
        self.keyvault_data_client.purge_deleted_certificate(vault.properties.vault_uri, cert_to_purge)
        print('purged certificate {}'.format(cert_to_purge))

        # list the vaults certificate
        keys = self.keyvault_data_client.get_certificates(vault.properties.vault_uri)
        print('certificates: \n{}'.format(self._serialize(certs)))

    def _wait_on_delete_completed(self, vault_uri, entity_type, entity_name):
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

    def _wait_on_recover_completed(self, vault_uri, entity_type, entity_name):
        if entity_type == 'secret':
            get_func = self.keyvault_data_client.get_secret
            args = (vault_uri, entity_name, KeyVaultId.version_none)
        elif entity_type == 'key':
            get_func = self.keyvault_data_client.get_key
            args = (vault_uri, entity_name, KeyVaultId.version_none)
        elif entity_type == 'certificate':
            get_func = self.keyvault_data_client.get_certificate
            args = (vault_uri, entity_name, KeyVaultId.version_none)
        else:  # entity_type == 'vault'
            get_func = self.keyvault_mgmt_client.vaults.get
            args = (entity_name, self.config.location)
        self._poll_while_404(get_func, args)
        
    def _poll_while_404(self, func, args=(), retry_wait=10, max_retries=10):
        for x in range(max_retries):
            try:
                return func(*args[0:]) 
            except KeyVaultErrorException as e:
                if not e.response.status_code == 404:
                    raise e
                time.sleep(retry_wait)


if __name__ == "__main__":
    run_all_samples([SoftDeleteSample()])

