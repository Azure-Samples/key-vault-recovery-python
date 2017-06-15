# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
import json
import time
import inspect
import traceback
import azure.mgmt.keyvault.models
import azure.keyvault.models
from key_vault_sample_config import KeyVaultSampleConfig
from haikunator import Haikunator
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault import KeyVaultClient, KeyVaultAuthentication
from msrest.exceptions import ClientRequestError
from msrestazure.azure_active_directory import ServicePrincipalCredentials
from msrest.paging import Paged
from msrest.serialization import Serializer
from azure.mgmt.keyvault.models import AccessPolicyEntry, VaultProperties, Sku, KeyPermissions, SecretPermissions, \
    CertificatePermissions, Permissions, VaultCreateOrUpdateParameters

SECRET_PERMISSIONS_ALL = [perm.value for perm in SecretPermissions]
KEY_PERMISSIONS_ALL = [perm.value for perm in KeyPermissions]
CERTIFICATE_PERMISSIONS_ALL = [perm.value for perm in CertificatePermissions]

def keyvaultsample(f):
    def wrapper(self):
        try:
            print('--------------------------------------------------------------------')
            print('RUNNING: {}'.format(f.__name__))
            print('--------------------------------------------------------------------')

            f(self)
        except Exception as e:
            print('ERROR: running sample failed with raised exception:')
            traceback.print_exception(type(e), e, e.__traceback__)
    wrapper.__name__ = f.__name__
    wrapper.kv_sample = True
    return wrapper

class KeyVaultSampleBase(object):
    """Base class for Key Vault samples, provides common functionality needed across Key Vault sample code

    :ivar config: Azure subscription id for the user intending to run the sample
    :vartype config: :class: `KeyVaultSampleConfig`q
    
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
        models = {}
        models.update({k: v for k, v in azure.keyvault.models.__dict__.items() if isinstance(v, type)})
        models.update({k: v for k, v in azure.mgmt.keyvault.models.__dict__.items() if isinstance(v, type)})

        self._serializer = Serializer(models)

    def run_samples(self, selected=None):
        samples_to_run = [m for name, m in inspect.getmembers(self) if getattr(m, 'kv_sample', False) and (not selected or name in selected)]

        for sample in samples_to_run:
            sample()

    def setup_sample(self):
        """
        Provides common setup for Key Vault samples, such as creating rest clients, creating a sample resource group
        if needed, and ensuring proper access for the service principal.
         
        :return: None 
        """
        if not self._setup_complete:
            self.data_creds = None
            self.mgmt_creds = ServicePrincipalCredentials(client_id=self.config.client_id, secret=self.config.client_secret,
                                                          tenant=self.config.tenant_id)
            self.resource_mgmt_client = ResourceManagementClient(self.mgmt_creds, self.config.subscription_id)

            # ensure the service principle has key vault as a valid provider
            self.resource_mgmt_client.providers.register('Microsoft.KeyVault')

            # ensure the intended resource group exists
            self.resource_mgmt_client.resource_groups.create_or_update(self.config.group_name, {'location': self.config.location})

            self.keyvault_mgmt_client = KeyVaultManagementClient(self.mgmt_creds, self.config.subscription_id)
            
            def auth_callack(server, resource, scope):
                self.data_creds = self.data_creds or ServicePrincipalCredentials(client_id=self.config.client_id,
                                                                                 secret=self.config.client_secret,
                                                                                 tenant=self.config.tenant_id,
                                                                                 resource=resource)
                token = self.data_creds.token
                return token['token_type'], token['access_token']

            self.keyvault_data_client = KeyVaultClient(KeyVaultAuthentication(auth_callack))

            self._setup_complete = True


    def create_vault(self):
        """
        Creates a new key vault with a unique name, granting full permissions to the current credentials
        :return: a newly created key vault
        :rtype: :class:`Vault <azure.keyvault.generated.models.Vault>`
        """
        vault_name = KeyVaultSampleBase.get_unique_name()

        # setup vault permissions for the access policy for the sample service principle
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

        print('Creating vault: {}'.format(vault_name))
        vault = self.keyvault_mgmt_client.vaults.create_or_update(self.config.group_name, vault_name, parameters)

        # wait for vault DNS entry to be created
        # see issue: https://github.com/Azure/azure-sdk-for-python/issues/1172
        self._poll_for_vault_connection(vault.properties.vault_uri)

        self._print_obj(vault)

        return vault

    def _print_obj(self, obj):
        print(self._serialize(obj))

    def _poll_for_vault_connection(self, vault_uri, retry_wait=10, max_retries=4):
        
        last_error = None
        for x in range(max_retries - 1):
            try:
                # sleep first to avoid inproper DNS caching
                time.sleep(retry_wait)
                self.keyvault_data_client.get_secrets(vault_uri)
                return
            except ClientRequestError as e:
                print('vault connection not available')
                last_error = e
        raise last_error

    @staticmethod
    def get_unique_name(prefix=''):
        """
        Generates a unique name for azure entities
        :return: a generated name suitable for naming azure entities 
        """
        return prefix + Haikunator().haikunate(delimiter='-')

    def _serialize(self, obj):
        if isinstance(obj, Paged):
            serialized = [self._serialize(i) for i in list(obj)]
        else:
            serialized = self._serializer.body(obj, type(obj).__name__)
        return json.dumps(serialized, indent=4, separators=(',', ': '))

