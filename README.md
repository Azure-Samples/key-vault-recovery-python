---
services: keyvault
platforms: python
author: schaabs
---
# Managing Soft Delete Enabled Key Vaults using the Azure Python SDK

This sample repo includes sample code demonstrating how to utilize the soft delete feature of Azure Key Vault to recover and purge deleted vaults, 
secrets, keys and certificates using the [Azure Python SDK](https://azure.microsoft.com/en-us/develop/python/). Some common scenarios this repo intends to target are:

* Backing up and restoring key vault secrets and keys
* Enabling soft delete when creating a new key vault
* Enabling soft delete on an existing key vault
* Recovering or purging deleted vaults
* Recovering or purging of key vault secrets, keys, and certificates

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
