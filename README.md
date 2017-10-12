---
services: key-vault
platforms: python
author: schaabs
---
# Recovery scenario samples for Azure Key Vault using the Azure Python SDK

This sample repo includes sample code demonstrating how to utilize the soft delete and backup restore features of Azure Key Vault to backup, restore, recover, and purge deleted vaults, 
secrets, keys and certificates using the [Azure Python SDK](https://azure.microsoft.com/en-us/develop/python/). Some common scenarios this repo intends to target are:

* Backing up and restoring key vault secrets and keys
* Enabling soft delete when creating a new key vault
* Enabling soft delete on an existing key vault
* Recovering or purging deleted vaults
* Recovering or purging of key vault secrets, keys, and certificates

## Samples in this repo
backup_restore_sample.py:

        backup_restore_key -- backs up a key vault key and restores it to another key vault
        backup_restore_secret -- backs up a key vault secret and restores it to another key vault

soft_delete_sample.py:

        create_soft_delete_enabled_vault -- creates a key vault which has soft delete enabled so that the vault as well as all of its keys,
        certificates and secrets are recoverable
        enable_soft_delete_on_existing_vault -- enables soft delete on an existing vault
        deleted_vault_recovery -- a sample of enumerating, retrieving, recovering and purging deleted key vaults
        deleted_certificate_recovery -- a sample of enumerating, retrieving, recovering and purging deleted certificates from a key vault
        deleted_key_recovery -- a sample of enumerating, retrieving, recovering and purging deleted keys from a key vault
        deleted_secret_recovery -- a sample of enumerating, retrieving, recovering and purging deleted secrets from a key vault

## Running The samples
1. If you don't already have it, [install Python](https://www.python.org/downloads/).

2. We recommend using a [virtual environment](https://docs.python.org/3/tutorial/venv.html) to run this example, but it's not mandatory. You can initialize a virtual environment this way:

    ```
    pip install virtualenv
    virtualenv mytestenv
    cd mytestenv
    source bin/activate
    ```

3. Clone the repository.

    ```
    git clone https://github.com/Azure-Samples/key-vault-recovery-python.git
    ```

4. Install the dependencies using pip.

    ```
    cd key-vault-recovery-python
    pip install -r requirements.txt
    ```

5. Create an Azure service principal, using 
[Azure CLI](http://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal-cli/),
[PowerShell](http://azure.microsoft.com/documentation/articles/resource-group-authenticate-service-principal/)
or [Azure Portal](http://azure.microsoft.com/documentation/articles/resource-group-create-service-principal-portal/).

6. Export these environment variables into your current shell. 

    ```
    export AZURE_TENANT_ID={your tenant id}
    export AZURE_CLIENT_ID={your service principal AppID}
    export AZURE_CLIENT_OID={your service principal OID}
    export AZURE_CLIENT_SECRET={your application key}
    export AZURE_SUBSCRIPTION_ID={your subscription id}
    ```

7. Run the samples, optionally specifying a space delimited list of specific samples to run.

    ```
    python run_all_samples.py [samplename[ samplename...]]
    ```

## Minimum Requirements
Python 2.7, 3.3, or 3.4.
To install Python, please go to https://www.python.org/downloads/

## More information

* What is Key Vault? - https://docs.microsoft.com/en-us/azure/key-vault/key-vault-whatis
* Get started with Azure Key Vault - https://docs.microsoft.com/en-us/azure/key-vault/key-vault-get-started
* Azure Key Vault General Documentation - https://docs.microsoft.com/en-us/azure/key-vault/
* Azure Key Vault REST API Reference - https://docs.microsoft.com/en-us/rest/api/keyvault/
* Azure SDK for Python Documentation - http://azure-sdk-for-python.readthedocs.io/en/latest/
* Azure Active Directory Documenation - https://docs.microsoft.com/en-us/azure/active-directory/
  
# Contributing

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information 
see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) 
with any additional questions or comments.
