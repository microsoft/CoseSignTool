# Error Code Reference

## Validation Error Codes

These error codes are returned in `ValidationResult.Failures` during staged validation.

| Code | Stage | Meaning | Remediation |
|------|-------|---------|-------------|
| `NO_SIGNING_KEY_RESOLVED` | Key Material Resolution | No signing key found in message headers | Ensure message contains x5chain or x5t header with valid certificates |
| `TRUST_PLAN_NOT_SATISFIED` | Signing Key Trust | Certificate chain failed trust policy | Check certificate validity, trust anchors, and policy requirements |
| `NO_APPLICABLE_SIGNATURE_VALIDATOR` | Signature | No validator found for this message type | Ensure correct verification provider is active for the message format |
| `SIGNATURE_VERIFICATION_FAILED` | Signature | Cryptographic signature is invalid | Message may be corrupted or tampered. Re-sign if you have access to the signing key |
| `SIGNATURE_MISSING_PAYLOAD` | Signature | Detached signature but no payload provided | Provide `--payload <file>` when verifying detached signatures |

## CLI Exit Codes

| Code | Name | Meaning |
|------|------|---------|
| 0 | Success | Operation completed successfully |
| 1 | GeneralError | Unexpected error occurred |
| 2 | InvalidArguments | Invalid command-line arguments provided |
| 3 | FileNotFound | Required file was not found |
| 4 | CertificateNotFound | Required certificate was not found |
| 5 | CertificateError | Error loading or using certificate |
| 10 | SigningFailed | Signing operation failed |
| 20 | ValidationFailed | Validation operation failed |
| 21 | InvalidSignature | Signature verification failed — signature is invalid |
| 22 | VerificationFailed | Verification operation failed |
| 23 | CertificateExpired | Signing certificate has expired |
| 24 | UntrustedCertificate | Certificate chain not trusted |
| 30 | PluginError | Plugin loading or execution failed |
| 40 | InspectionFailed | Inspection operation failed |

## Troubleshooting

For any error, add `-vv --log-file debug.log` to capture detailed diagnostics:

```
cosesigntool verify x509 document.cose --payload document.txt -vv --log-file debug.log
```

Review the log file for stage-by-stage validation results with timing and component details.

### Common Issues

**Exit code 21 (InvalidSignature):**
The cryptographic signature does not verify against the extracted key material.
This usually means the message was modified after signing, or the wrong key is being used for verification.

**Exit code 24 (UntrustedCertificate):**
The signing certificate chain does not satisfy the trust policy.
Check that the certificate is not expired, the chain builds to a trusted root, and any custom trust policy requirements are met.
Use `--trust-roots` to specify custom CA bundles if needed.

**Exit code 3 (FileNotFound) on detached signatures:**
Detached signatures require the original payload to be provided via `--payload <file>`.
Indirect signatures (hash envelope) embed the payload hash and do not require the payload for signature verification, but do require it for payload hash verification.