# Fixtures

This directory holds sanitized test data.

- `imports/`: export samples from supported import formats.
- `exports/`: documented plaintext export examples containing synthetic values
  only. `keptnear-plaintext-v1.json` demonstrates the complete typed JSON
  envelope and uses no production credential.
- `vaults/`: generated pre-alpha vault directories and golden fixtures,
  including `golden-vault-v1.pswvault`, a sanitized encrypted fixture with
  synthetic test-only data, and `golden-vault-v2.pswvault`, the current released
  schema fixture generated through the v1 migration. The registries remain
  separate: `supported-source-versions.json` inventories migration sources
  while `released-format-fixtures.json` inventories current public format
  evidence.
- `machine-access/`: synthetic human-control, controller-authentication,
  LaunchAgent, and component-manifest compatibility fixtures. Each contract has
  one accepted version 1 sample and one unsupported future-version sample.

Real user vaults, real passwords, and real export files must not be committed.
