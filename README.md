# Apigee Key Rotation with HashiCorp Vault
## Overview
This service automates Apigee Consumer Key and Secret rotation and securely stores the new credentials in HashiCorp Vault. Since Vault does not provide a native Apigee backend, this custom solution handles key lifecycle management while integrating with Vault’s KV2 secrets engine.

## How It Works
<img width="1100" alt="image" src="https://github.com/user-attachments/assets/facf6b1f-e32b-4ad9-8386-730991260bc6" />  

#
* **Key Rotation**: Periodically creates a new Apigee key, associates it with the Developer App, and removes old keys.
* **Vault Integration**: Stores the latest Consumer Key and Secret in Vault’s KV2 backend.
* **TTL-Based Cleanup**: Ensures expired keys are removed at scheduled intervals.
* **Metrics & Monitoring**: Exposes Prometheus metrics for key TTL tracking.
