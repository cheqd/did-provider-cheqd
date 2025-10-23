# Bitstring Status List Examples

## Create and Verify Bitstring Status List

### Create Unencrypted List

`veramo execute -m cheqdCreateStatusList -f examples/bitstring-status-list/create/create-list-unencrypted.json`

### Create Encrypted List

`veramo execute -m cheqdCreateStatusList -f examples/bitstring-status-list/create/create-list-encrypted.json`

### Verify Unencrypted Bitstring Status List Credential

`veramo execute -m cheqdVerifyStatusListCredential -f examples/bitstring-status-list/credential/verify/statuslist-credential.json`

### Verify Encrypted Bitstring Status List Credential

`veramo execute -m cheqdVerifyStatusListCredential -f examples/bitstring-status-list/credential/verify/statuslist-credential-encrypted.json`

## Issue and Verify Credential

### Issue Credential with Unencrypted List

`veramo execute -m cheqdIssueCredentialWithStatusList -f examples/bitstring-status-list/credential/issue/credential-unencrypted.json`

### Issue Credential with Encrypted List

`veramo execute -m cheqdIssueCredentialWithStatusList -f examples/bitstring-status-list/credential/issue/credential-encrypted.json`

### Verify Credential with Unencrypted List

`veramo execute -m cheqdVerifyCredentialWithStatusList -f examples/bitstring-status-list/credential/verify/credential-unencrypted.json`

### Verify Credential with Encrypted List

`veramo execute -m cheqdVerifyCredentialWithStatusList -f examples/bitstring-status-list/credential/verify/credential-encrypted.json`

### Get Credential Status

`veramo execute -m cheqdCheckBitstringStatus -f examples/bitstring-status-list/credential/verify/credentialstatus-unencrypted.json`

## Update Credential Status

### Suspend Credential

`veramo execute -m cheqdUpdateCredentialWithStatusList -f examples/bitstring-status-list/credential/update-status/suspend-credential-unencrypted.json`

### Unsuspend Credential

`veramo execute -m cheqdUpdateCredentialWithStatusList -f examples/bitstring-status-list/credential/update-status/unsuspend-credential-unencrypted.json`

### Revoke Credential

`veramo execute -m cheqdUpdateCredentialWithStatusList -f examples/bitstring-status-list/credential/update-status/revoke-credential-unencrypted.json`

## Bulk Update Credential Status

### Suspend Credentials

`veramo execute -m cheqdBulkUpdateCredentialsWithStatusList -f examples/bitstring-status-list/credential/update-status/suspend-bulk-credentials-unencrypted.json`

### Unsuspend Credentials

`veramo execute -m cheqdBulkUpdateCredentialsWithStatusList -f examples/bitstring-status-list/credential/update-status/unsuspend-bulk-credentials-unencrypted.json`

### Revoke Credentials

`veramo execute -m cheqdBulkUpdateCredentialsWithStatusList -f examples/bitstring-status-list/credential/update-status/revoke-bulk-credentials-unencrypted.json`

## Verify Presentation

`veramo execute -m cheqdVerifyPresentationWithStatusList -f examples/bitstring-status-list/presentation/verify-presentation-unencrypted.json`
