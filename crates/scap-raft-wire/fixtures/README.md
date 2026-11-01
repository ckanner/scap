# Synthetic public certificate

`leaf.pem` is a self-signed public certificate generated solely for bounded DER
parser unit tests. No private key is stored in this repository. It is not a
production credential, CA, or mTLS trust configuration.

Generated using OpenSSL `req -x509 -newkey rsa:2048`, subject
`CN=SCAP wire unit fixture`, validity 2026-11-01 07:38:25 UTC through
2036-10-29 07:38:25 UTC. DER SHA-256, independently recorded by OpenSSL:

```text
3bdeef20da77563d99f76ffdff6abeba7dd701ef7f870f4437256929627090dd
```

Tests use explicit timestamps. They do not depend on this certificate being
valid at the wall-clock time when tests run, and do not treat parsing as
cryptographic verification.
