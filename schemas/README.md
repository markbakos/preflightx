# Report schemas

- `scan-report-v2.schema.json` is PreflightX's versioned JSON report contract.
- `sarif-schema-2.1.0.json` is the OASIS SARIF 2.1.0 Errata 01 schema, copied from <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json>.

The test suite validates generated JSON and SARIF reports against these local files. Schema checks make no network requests.
