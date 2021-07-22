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

from azure.mgmt.keyvault.models import VaultProperties, VaultCreateOrUpdateParameters, Sku, SkuName
from key_vault_sample_base import KeyVaultSampleBase, keyvaultsample, get_name, run_all_samples
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.certificates import CertificateClient, CertificatePolicy


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
        print('creating soft delete enabled vault: {}'.format(vault_name))

        vault = self.create_vault()
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
        vault = self.keyvault_mgmt_client.vaults.begin_create_or_update(self.config.group_name,
                                                          vault.name,
                                                          VaultCreateOrUpdateParameters(location=vault.location,
                                                                                        properties=vault.properties)).result()

        print('updated vault {} enable_soft_delete={}'.format(vault.name, vault.properties.enable_soft_delete))


    @keyvaultsample
    def deleted_vault_recovery(self):
        """
        a sample of enumerating, retrieving, recovering and purging deleted key vaults
        """
        # create vaults enabling the soft delete feature on each
        vault_to_recover = self.create_vault()
        vault_to_purge = self.create_vault()
        print('created vaults {} and {}'.format(vault_to_recover.name, vault_to_purge.name))

        # delete the vaults
        self.keyvault_mgmt_client.vaults.delete(self.config.group_name, vault_to_recover.name)
        print('Deleted vault: {}'.format(vault_to_recover.name))
        self.keyvault_mgmt_client.vaults.delete(self.config.group_name, vault_to_purge.name)
        print('Deleted vault: {}'.format(vault_to_purge.name))

        # list the deleted vaults
        deleted_vaults = self.keyvault_mgmt_client.vaults.list_deleted()
        for deleted_vault in deleted_vaults:
            print(deleted_vault.name)

        # get the details of a specific deleted vault
        deleted_info = self.keyvault_mgmt_client.vaults.get_deleted(vault_to_recover.name, vault_to_recover.location)
        print('Deleted vault: {}'.format(deleted_info.properties))

        # to restore the vault simply supply the group, location, and name and set the 'create_mode' vault property to 'recover'
        # setting this property will cause other properties passed to create_or_update to be ignored and will simply
        # restore the vault in the state it was when it was deleted
        recovery_properties = VaultProperties(tenant_id=self.config.tenant_id, sku=Sku(name=SkuName.standard.name), access_policies=[], create_mode='recover')
        recovery_parameters = VaultCreateOrUpdateParameters(location=deleted_info.properties.location,
                                                            properties=recovery_properties)
        recovered = self.keyvault_mgmt_client.vaults.begin_create_or_update(self.config.group_name, deleted_info.name, recovery_parameters).result()
        print('Recovered vault: {}'.format(recovered.name))

        # list the deleted vaults again only the vault we intend to purge is still deleted
        deleted_vaults = self.keyvault_mgmt_client.vaults.list_deleted()
        for deleted_vault in deleted_vaults:
                    print(deleted_vault.name)

        # purge the last deleted vault
        self.keyvault_mgmt_client.vaults.begin_purge_deleted(vault_to_purge.name, vault_to_purge.location)
        print('Purged vault: {}'.format(vault_to_purge.name))

        # verify no deleted vaults remain
        deleted_vaults = self.keyvault_mgmt_client.vaults.list_deleted()
        for deleted_vault in deleted_vaults:
            print(deleted_vault.name)


    @keyvaultsample
    def deleted_secret_recovery(self):
        """
        a sample of enumerating, retrieving, recovering and purging deleted secrets from a key vault
        """
        # create a vault enabling the soft delete feature
        vault = self.create_vault()

        # create a secret client
        credential = DefaultAzureCredential()
        secret_client = SecretClient(vault_url=vault.properties.vault_uri, credential=credential)

        # create secrets in the vault
        secret_to_recover = get_name('secret')
        secret_to_purge = get_name('secret')

        secret = secret_client.set_secret(secret_to_recover, "secret to restore")
        print('created secret {}'.format(secret.name))

        secret = secret_client.set_secret(secret_to_purge, "secret to purge")
        print('created secret {}'.format(secret.name))

        # list the name of all of the secrets in the client's vault
        secret_properties = secret_client.list_properties_of_secrets()
        print("all of the secrets in the client's vault:")
        for secret_property in secret_properties:
            print(secret_property.name)

        # delete the secrets
        delete_secret_poller = secret_client.begin_delete_secret(secret_to_recover)
        deleted_secret = delete_secret_poller.result()
        delete_secret_poller.wait()
        print('deleted secret {}'.format(deleted_secret.name))

        delete_secret_poller = secret_client.begin_delete_secret(secret_to_purge)
        deleted_secret = delete_secret_poller.result()
        delete_secret_poller.wait()
        print('deleted secret {}'.format(deleted_secret.name))

        # list the deleted secrets
        deleted_secrets = secret_client.list_deleted_secrets()
        print("all of the deleted secrets in the client's vault:")
        for deleted_secret in deleted_secrets:
            print(deleted_secret.name)

        # recover a deleted secret
        recover_secret_poller = secret_client.begin_recover_deleted_secret(secret_to_recover)
        recovered_secret = recover_secret_poller.result()
        recover_secret_poller.wait()

        print('recovered secret {}'.format(recovered_secret.name))

        # purge a deleted secret
        secret_client.purge_deleted_secret(secret_to_purge)
        print('purged secret {}'.format(secret_to_purge))

        # list the name of all of the secrets in the client's vault
        secret_properties = secret_client.list_properties_of_secrets()
        print("all of the secrets in the client's vault:")
        for secret_property in secret_properties:
            print(secret_property.name)


    @keyvaultsample
    def deleted_key_recovery(self):
        """
        a sample of enumerating, retrieving, recovering and purging deleted keys from a key vault
        """
        # create a vault enabling the soft delete feature
        vault = self.create_vault()
        
        # create a key client
        credential = DefaultAzureCredential()
        key_client = KeyClient(vault_url=vault.properties.vault_uri, credential=credential)

        # create keys in the vault
        key_to_recover = get_name('key')
        key_to_purge = get_name('key')

        key = key_client.create_key(key_to_recover, 'RSA')
        print('created key {}'.format(key.name))

        key = key_client.create_key(key_to_purge, 'RSA')
        print('created key {}'.format(key.name))

        # list the vault keys
        keys = key_client.list_properties_of_keys()
        print("keys:")
        for key in keys:
            print(key.name)

        # delete the keys
        key_client.begin_delete_key(key_to_recover).wait()
        print('deleted key {}'.format(key_to_recover))

        key_client.begin_delete_key(key_to_purge).wait()
        print('deleted key {}'.format(key_to_purge))

        # list the deleted keys
        deleted_keys = key_client.list_deleted_keys()
        print("deleted keys:")
        for deleted_key in deleted_keys:
            print(deleted_key.name)

        # recover a deleted key
        recover_key_poller = key_client.begin_recover_deleted_key(key_to_recover)
        recovered_key = recover_key_poller.result()
        recover_key_poller.wait()
        print('recovered key {}'.format(recovered_key.name))

        # purge a deleted key
        key_client.purge_deleted_key(key_to_purge)
        print('purged key {}'.format(key_to_purge))

        # list the vaults key
        keys = key_client.list_properties_of_keys()
        print("keys:")
        for key in keys:
            print(key.name)


    @keyvaultsample
    def deleted_certificate_recovery(self):
        """
        a sample of enumerating, retrieving, recovering and purging deleted certificates from a key vault 
        """
        # create a vault enabling the soft delete feature
        vault = self.create_vault()

        # create a certificate client
        credential = DefaultAzureCredential()
        certificate_client = CertificateClient(vault_url=vault.properties.vault_uri, credential=credential)

        # create certificates in the vault
        cert_to_recover = get_name('cert')
        cert_to_purge = get_name('cert')

        create_certificate_poller = certificate_client.begin_create_certificate(cert_to_recover, policy=CertificatePolicy.get_default())
        print('created certificate {}'.format(create_certificate_poller.result()))

        create_certificate_poller = certificate_client.begin_create_certificate(cert_to_purge, policy=CertificatePolicy.get_default())
        print('created certificate {}'.format(create_certificate_poller.result()))

        # list the vault certificates
        certificates = certificate_client.list_properties_of_certificates()
        print('list the vault certificates')
        for certificate in certificates:
            print(certificate.name)

        # delete the certificates
        deleted_certificate_poller  = certificate_client.begin_delete_certificate(cert_to_recover)
        deleted_certificate = deleted_certificate_poller.result()
        deleted_certificate_poller.wait()
        print('deleted certificate {}'.format(deleted_certificate.name))

        deleted_certificate_poller  = certificate_client.begin_delete_certificate(cert_to_purge)
        deleted_certificate = deleted_certificate_poller.result()
        deleted_certificate_poller.wait()
        print('deleted certificate {}'.format(deleted_certificate.name))

        # list the deleted certificates
        deleted_certs = certificate_client.list_deleted_certificates()
        print('list the deleted certificates')
        for deleted_cert in deleted_certs:
            print(deleted_cert.name)

        # recover a deleted certificate
        recovered_certificate_poller = certificate_client.begin_recover_deleted_certificate(cert_to_recover)
        recovered_certificate_certificate = recovered_certificate_poller.result()
        recovered_certificate_poller.wait()
        print('recovered certificate {}'.format(recovered_certificate_certificate.name))

        # purge a deleted certificate
        certificate_client.purge_deleted_certificate(cert_to_purge)
        print('purged certificate {}'.format(cert_to_purge))

        # list the vault certificates
        certificates = certificate_client.list_properties_of_certificates()
        print('list the vault certificates')
        for certificate in certificates:
            print(certificate.name)


if __name__ == "__main__":
    run_all_samples([SoftDeleteSample()])

