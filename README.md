# Apigee Key Rotation with HashiCorp Vault
## Overview
This service automates Apigee Consumer Key and Secret rotation and securely stores the new credentials in HashiCorp Vault. Since Vault does not provide a native Apigee backend, this custom solution handles key lifecycle management while integrating with Vault’s KV2 secrets engine.

## How It Works
> **Step 1**:\
> Initializes Apigee using HTTP client, vault client, validates all environment variables, and uses ValidateConfig to build the ExpirationTracker map.

> **Step 2**:\
> **ValidateConfig** builds ExpirationTracker map under different situations like i) to onboard an app to vault, ii) patch stale expiration time, etc. All this checks are performed once during entrypoint.
ValidateConfig uses batchReadVaultData to read vault concurrently which returns a map with Vault data. This map provides the data to accomplish all the tasks in this function.
**ValidateConfig** also uses **patchVaultExpiration** to update stale  expiration time caught during entrypoint. It then finally calls expirationWatcher.

>**Step 3**:\
> **expirationWatcher** is used to perform two tasks. i) tracking the expiration of key, secret and calling rotate function when key is expired and ii) Deletes the old key from apigee.  Both these tasks are performed periodically.  
env **KEY_ROTATION_CHECK_INTERVAL**: how frequently the code should check for password expiration, set as 1m.\
env **KEY_DELETION_INTERVAL**:  how frequently the code should delete  duplicate keys.\
env **TTL_CRON**: User input to set expiration time of key.\
expirationWatcher also uses **rotateApigeeKeys** to rotate the keys.

> **Step 4**:\
> **rotateApigeeKeys** function creates the Consumer Key, Secret for a Developer App. Along with create key, it also associates products.  
**rotateApigeeKeys** then writes the keys, secret and expirationTime to Vault via **WriteToVault**. 


#
* **Key Rotation**: Periodically creates a new Apigee key, associates it with the Developer App, and removes old keys.
* **Vault Integration**: Stores the latest Consumer Key and Secret in Vault’s KV2 backend.
* **TTL-Based Cleanup**: Ensures expired keys are removed at scheduled intervals.
* **Metrics & Monitoring**: Exposes Prometheus metrics for key TTL tracking.
