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
