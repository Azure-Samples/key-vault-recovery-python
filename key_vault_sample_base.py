# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

from key_vault_sample_config import KeyVaultSampleConfig
from haikunator import Haikunator
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault.generated import KeyVaultClient
from msrestazure.azure_active_directory import ServicePrincipalCredentials
from azure.mgmt.keyvault.models import AccessPolicyEntry, VaultProperties, Sku, KeyPermissions, SecretPermissions, \
    CertificatePermissions, Permissions, VaultCreateOrUpdateParameters


class KeyVaultSampleBase(object):
    """Base class for Key Vault samples, provides common functionality needed across Key Vault sample code

    :ivar config: Azure subscription id for the user intending to run the sample
    :vartype config: :class: `KeyVaultSampleConfig`
    
    :ivar credentials: Azure Active Directory credentials used to authenticate with Azure services
    :vartype credentials: :class: `ServicePrincipalCredentials 
     <msrestazure.azure_active_directory.ServicePrincipalCredentials>`
    
    :ivar keyvault_data_client: Key Vault data client used for interacting with key vaults 
    :vartype keyvault_data_client: :class: `KeyVaultClient <azure.keyvault.KeyVaultClient>`
    
    :ivar keyvault_mgmt_client: Key Vault management client used for creating and managing key vaults 
    :vartype keyvault_mgmt_client:  :class: `KeyVaultManagementClient <azure.mgmt.keyvault.KeyVaultManagementClient>`
    
    :ivar resource_mgmt_client: Azure resource management client used for managing azure resources, access, and groups 
    :vartype resource_mgmt_client:  :class: `ResourceManagementClient <azure.mgmt.resource.ResourceManagementClient>`
    """
    def __init__(self):
        self.config = KeyVaultSampleConfig()
        self.credentials = None
        self.keyvault_data_client = None
        self.keyvault_mgmt_client = None
        self.resource_mgmt_client = None
        self._setup_complete = False
        self._haikunator = Haikunator()

    def setup_sample(self):
        """
        Provides common setup for Key Vault samples, such as creating rest clients, creating a sample resource group
        if needed, and ensuring proper access for the service principal.
         
        :return: None 
        """
        if not self._setup_complete:
            self.credentials = ServicePrincipalCredentials(self.config.client_id, self.config.client_secret)
            self.resource_mgmt_client = ResourceManagementClient(self.credentials, self.subscription_id)

            # ensure the service principle has key vault as a valid provider
            self.resource_client.providers.register('Microsoft.KeyVault')

            # ensure the intended resource group exists
            self.resource_client.resource_groups.create_or_update(self.config.group_name, {'location': self.config.location})

            self.keyvault_mgmt_client = KeyVaultManagementClient(self.credentials, self.config.subscription_id)
            self.keyvault_data_client = KeyVaultClient(self.credentials)

            self._setup_complete = True

    def create_vault(self):
        """
        Creates a new key vault with a unique name, granting full permissions to the current credentials
        :return: a newly created key vault
        :rtype: :class:`Vault <azure.keyvault.generated.models.Vault>`
        """
        vault_name = KeyVaultSampleBase.get_unique_name()

        permissions = Permissions()
        permissions.keys = [KeyPermissions.all]
        permissions.secrets = [SecretPermissions.all]
        permissions.certificates = [CertificatePermissions.all]

        policy = AccessPolicyEntry(self.config.tenant_id, self.config.client_oid, permissions)

        properties = VaultProperties(self.config.tenant_id, Sku(name='standard'), policies=[policy])

        parameters = VaultCreateOrUpdateParameters(self.config.location, properties)
        parameters.properties.enabled_for_deployment = True
        parameters.properties.enabled_for_disk_encryption = True
        parameters.properties.enabled_for_template_deployment = True

        vault = self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_namne, vault_name, parameters)

        return vault

    def get_unique_name(self):
        """
        Generates a unique name for azure entities
        :return: a generated name suitable for naming azure entities 
        """
        return self._haikunator.haikunate(delimiter='-')
