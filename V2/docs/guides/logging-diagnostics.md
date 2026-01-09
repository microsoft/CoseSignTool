# Logging and Diagnostics

CoseSignTool V2 provides comprehensive logging and diagnostics capabilities for troubleshooting, auditing, and monitoring signing and verification operations.

## Overview

The logging system supports:

- **Multiple verbosity levels** for console output
- **Structured log file output** in Text, JSON, or XML format
- **Per-provider log levels** (console vs file)
- **Microsoft.Extensions.Logging** integration for library consumers

---

## Console Verbosity

### Verbosity Levels

| Level | Option | LogLevel | Description |
|-------|--------|----------|-------------|
| 0 | `-q`, `--quiet` | None | Suppress all output except errors |
| 1 | (default) | Warning | Normal operation - warnings and errors |
| 2 | | Information | Verbose - informational messages |
| 3 | `-vv` | Debug | Debug output with detailed information |
| 4+ | `-vvv` | Trace | Full trace with maximum detail |

### Usage Examples

```bash
# Quiet mode - minimal output
cosesigntool verify document.cose -q

# Default - warnings and errors only
cosesigntool verify document.cose

# Debug verbosity
cosesigntool verify document.cose -vv

# Trace verbosity
cosesigntool verify document.cose -vvv

# Explicit verbosity level
cosesigntool verify document.cose --verbosity 3
```

### Output by Verbosity Level

**Quiet Mode (`-q`):**
- Exit code only
- Critical errors to stderr

**Default (Level 1):**
- Warnings and errors
- Operation summary (success/failure)
- Startup banner

**Verbose (Level 2):**
- All default output
- Informational progress messages
- Validation stage results

**Debug (Level 3):**
- All verbose output
- Detailed validation information
- Plugin loading details
- Certificate chain details

**Trace (Level 4+):**
- All debug output
- Raw COSE header values
- Cryptographic operation details
- Performance timing

---

## Log File Output

### Basic Usage

Write all logs to a file for post-mortem analysis:

```bash
# Write logs to file (overwrites existing)
cosesigntool verify document.cose --log-file verify.log

# Append to existing log file
cosesigntool verify document.cose --log-file verify.log --log-file-append
```

### Log File Formats

The log file format follows the `--output-format` option:

```bash
# Text format (default)
cosesigntool verify document.cose --log-file verify.log --output-format text

# JSON format for parsing
cosesigntool verify document.cose --log-file verify.log --output-format json

# XML format
cosesigntool verify document.cose --log-file verify.log --output-format xml
```

> **Note**: The `--quiet` format is treated as `text` for log files since logs are for diagnostics.

### Log File Content

The log file **always** captures Debug level regardless of console verbosity:

```bash
# Console shows only warnings, log file captures everything
cosesigntool verify document.cose --log-file full-debug.log
```

This allows you to run quietly while maintaining full diagnostic capabilities.

### Text Log Format

```
2026-01-08 14:30:45.123 [Debug] CoseSignTool: CoseSignTool starting with verbosity level 1
2026-01-08 14:30:45.125 [Debug] CoseSignTool: CoseSignTool V2.0.0 (SHA256: abc123...)
2026-01-08 14:30:45.130 [Debug] PluginLoader: Loading plugins from: C:\tools\plugins
2026-01-08 14:30:45.145 [Information] Verify: Verifying signature: document.cose
2026-01-08 14:30:45.200 [Debug] Validation: Stage KeyMaterialResolution: Success
2026-01-08 14:30:45.210 [Debug] Validation: Stage KeyMaterialTrust: Success
2026-01-08 14:30:45.220 [Debug] Validation: Stage Signature: Success
2026-01-08 14:30:45.225 [Information] Verify: Verification succeeded
```

### JSON Log Format

```json
[
  {
    "timestamp": "2026-01-08T14:30:45.123Z",
    "level": "Debug",
    "category": "CoseSignTool",
    "message": "CoseSignTool starting with verbosity level 1"
  },
  {
    "timestamp": "2026-01-08T14:30:45.200Z",
    "level": "Debug",
    "category": "Validation",
    "message": "Stage KeyMaterialResolution: Success"
  }
]
```

### XML Log Format

```xml
<Logs>
  <LogEntry>
    <Timestamp>2026-01-08T14:30:45.123Z</Timestamp>
    <Level>Debug</Level>
    <Category>CoseSignTool</Category>
    <Message>CoseSignTool starting with verbosity level 1</Message>
  </LogEntry>
  <LogEntry>
    <Timestamp>2026-01-08T14:30:45.200Z</Timestamp>
    <Level>Debug</Level>
    <Category>Validation</Category>
    <Message>Stage KeyMaterialResolution: Success</Message>
  </LogEntry>
</Logs>
```

---

## Output Formats

### Structured Output

CoseSignTool supports structured output for automation:

```bash
# JSON output for parsing
cosesigntool verify document.cose --output-format json

# XML output
cosesigntool verify document.cose --output-format xml

# Text output (default, human-readable)
cosesigntool verify document.cose --output-format text

# Quiet output (exit code only)
cosesigntool verify document.cose --output-format quiet
```

### JSON Output Example

```json
{
  "command": "verify",
  "success": true,
  "signature": {
    "algorithm": "ES256",
    "contentType": "application/octet-stream"
  },
  "certificate": {
    "subject": "CN=Signer",
    "issuer": "CN=CA",
    "thumbprint": "ABC123...",
    "notBefore": "2025-01-01T00:00:00Z",
    "notAfter": "2026-01-01T00:00:00Z"
  },
  "validation": {
    "stages": {
      "keyMaterialResolution": { "success": true },
      "keyMaterialTrust": { "success": true },
      "signature": { "success": true },
      "postSignature": { "success": true }
    },
    "overall": { "success": true }
  }
}
```

### XML Output Example

```xml
<Result>
  <Command>verify</Command>
  <Success>true</Success>
  <Signature>
    <Algorithm>ES256</Algorithm>
    <ContentType>application/octet-stream</ContentType>
  </Signature>
  <Certificate>
    <Subject>CN=Signer</Subject>
    <Issuer>CN=CA</Issuer>
    <Thumbprint>ABC123...</Thumbprint>
    <NotBefore>2025-01-01T00:00:00Z</NotBefore>
    <NotAfter>2026-01-01T00:00:00Z</NotAfter>
  </Certificate>
  <Validation>
    <KeyMaterialResolution Success="true" />
    <KeyMaterialTrust Success="true" />
    <Signature Success="true" />
    <PostSignature Success="true" />
    <Overall Success="true" />
  </Validation>
</Result>
```

---

## Startup Banner

CoseSignTool displays a startup banner with version and hash information:

```
CoseSignTool V2.0.0
Binary SHA256: 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b
```

### Banner Behavior

| Verbosity | Console | Log File |
|-----------|---------|----------|
| Quiet (`-q`) | Hidden | Always logged at Debug |
| Normal (1+) | Shown | Always logged at Debug |

The banner provides:
- **Version identification** for support and troubleshooting
- **Binary hash** for integrity verification and forensics

---

## Library Integration

### Using ILoggerFactory

CoseSignTool V2 libraries accept `ILoggerFactory` for integration with your logging infrastructure:

```csharp
using Microsoft.Extensions.Logging;
using CoseSign1.Validation;

// Create your logger factory
var loggerFactory = LoggerFactory.Create(builder =>
{
    builder
        .AddConsole()
        .AddApplicationInsights()
        .SetMinimumLevel(LogLevel.Debug);
});

// Pass to validation builder
var validator = Cose.Sign1Message(loggerFactory)
    .ValidateCertificate(cert => cert.ValidateChain())
    .OverrideDefaultTrustPolicy(policy)
    .Build();
```

### ASP.NET Core Integration

```csharp
// In Startup.cs or Program.cs
services.AddSingleton<ICoseSign1Validator>(sp =>
{
    var loggerFactory = sp.GetRequiredService<ILoggerFactory>();
    
    return Cose.Sign1Message(loggerFactory)
        .ValidateCertificate(cert => cert.ValidateChain())
        .OverrideDefaultTrustPolicy(policy)
        .Build();
});
```

### Logging Categories

CoseSignTool uses structured logging categories:

| Category | Description |
|----------|-------------|
| `CoseSignTool` | Main application logging |
| `CoseSignTool.Commands.Verify` | Verify command |
| `CoseSignTool.Commands.Sign` | Sign command |
| `CoseSignTool.Commands.Inspect` | Inspect command |
| `CoseSign1.Validation` | Validation framework |
| `CoseSign1.Validation.Trust` | Trust evaluation |
| `CoseSign1.Certificates` | Certificate operations |
| `PluginLoader` | Plugin discovery and loading |

### Filtering by Category

```csharp
var loggerFactory = LoggerFactory.Create(builder =>
{
    builder
        .AddConsole()
        .AddFilter("CoseSign1.Validation", LogLevel.Debug)
        .AddFilter("CoseSign1.Certificates", LogLevel.Warning);
});
```

---

## Diagnostic Scenarios

### Debugging Validation Failures

```bash
# Full debug output with log file
cosesigntool verify document.cose -vvv --log-file debug.log

# Check log for detailed validation stages
cat debug.log
```

### Auditing Signing Operations

```bash
# JSON log for structured audit trail
cosesigntool sign-pfx --pfx cert.pfx --payload document.txt \
    --output document.cose \
    --log-file audit.json \
    --output-format json
```

### Plugin Loading Issues

```bash
# Trace level shows plugin discovery details
cosesigntool verify document.cose -vvv

# Example output:
# [Debug] PluginLoader: Scanning directory: C:\tools\plugins
# [Debug] PluginLoader: Found plugin assembly: CoseSignTool.Custom.Plugin.dll
# [Debug] PluginLoader: Loading plugin: CustomPlugin v1.0.0
# [Debug] PluginLoader: Registered signing command: sign-custom
```

### Certificate Chain Debugging

```bash
# Debug verbosity shows chain building details
cosesigntool verify document.cose -vv

# Example output:
# [Debug] CertificateChainValidator: Building chain for: CN=Signer
# [Debug] CertificateChainValidator: Chain element 0: CN=Signer (Leaf)
# [Debug] CertificateChainValidator: Chain element 1: CN=Intermediate CA
# [Debug] CertificateChainValidator: Chain element 2: CN=Root CA (Trusted)
# [Debug] CertificateChainValidator: Chain status: Valid
```

---

## Best Practices

### 1. Always Use Log Files in Production

```bash
# Production verification with full logging
cosesigntool verify document.cose \
    --log-file /var/log/cosesigntool/verify-$(date +%Y%m%d-%H%M%S).log
```

### 2. Use JSON Format for Automation

```bash
# Parse results programmatically
result=$(cosesigntool verify document.cose --output-format json)
success=$(echo "$result" | jq '.success')
```

### 3. Separate Console and File Verbosity

- Keep console output minimal for operators
- Capture full debug logs to file for post-mortem analysis

```bash
# Quiet console, full debug in log file
cosesigntool verify document.cose -q --log-file debug.log
```

### 4. Rotate Log Files

Use `--log-file` with timestamps or external log rotation:

```bash
# Timestamped log files
cosesigntool verify document.cose \
    --log-file "verify-$(date +%Y%m%d-%H%M%S).log"
```

### 5. Monitor for Specific Patterns

Search log files for issues:

```bash
# Find trust failures
grep "TRUST_POLICY_NOT_SATISFIED" *.log

# Find certificate issues
grep "cert\." *.log | grep -i "fail\|error\|invalid"
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `COSESIGNTOOL_LOG_LEVEL` | Default log level (Debug, Information, Warning, Error) |
| `COSESIGNTOOL_LOG_FILE` | Default log file path |

---

## High-Performance Logging Pattern

CoseSignTool V2 uses the `[LoggerMessage]` source generator pattern throughout the codebase for high-performance logging. This pattern avoids boxing, string interpolation, and delegate allocation at runtime.

### When to Use

Use `[LoggerMessage]` when:
- Creating new validators, services, or other components that log frequently
- The class has an instance `ILogger<T>` field
- Performance is a concern (hot paths, high-throughput scenarios)

### Implementation Pattern

```csharp
using Microsoft.Extensions.Logging;

public sealed partial class MyValidator : IValidator
{
    private readonly ILogger<MyValidator> Logger;

    public MyValidator(ILogger<MyValidator>? logger = null)
    {
        Logger = logger ?? NullLogger<MyValidator>.Instance;
    }

    #region LoggerMessage methods

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Debug,
        Message = "Starting validation for {Thumbprint}")]
    private partial void LogValidationStarted(string thumbprint);

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Information,
        Message = "Validation succeeded in {ElapsedMs}ms")]
    private partial void LogValidationSucceeded(long elapsedMs);

    [LoggerMessage(
        EventId = 1003,
        Level = LogLevel.Warning,
        Message = "Validation failed: {ErrorCode} - {ErrorMessage}")]
    private partial void LogValidationFailed(string errorCode, string errorMessage);

    #endregion

    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        LogValidationStarted(thumbprint);
        
        // ... validation logic ...
        
        if (success)
        {
            LogValidationSucceeded(stopwatch.ElapsedMilliseconds);
        }
        else
        {
            LogValidationFailed(failure.ErrorCode, failure.Message);
        }
    }
}
```

### Key Requirements

1. **Partial class**: The class must be `partial` for source generation
2. **Partial methods**: Log methods must be `partial` and `private` (or `internal`)
3. **Unique EventIds**: Use unique event IDs per class (e.g., 1000-1099 for one class, 2000-2099 for another)
4. **Instance logger**: The logger must be an instance field, not passed as a parameter

### EventId Ranges by Component

| Component | EventId Range |
|-----------|---------------|
| CoseSign1Validator | 100-199 |
| CompositeValidator | 1000-1099 |
| AnySignatureValidator | 2000-2099 |
| CertificateChainValidator | 3000-3099 |
| CertificateChainFactory | 4000-4099 |
| PluginLoader | 5000-5099 |

### Avoid These Anti-Patterns

```csharp
// ❌ BAD: String interpolation (allocates)
Logger.LogDebug($"Validating {thumbprint}");

// ❌ BAD: Boxing value types
Logger.LogDebug("Elapsed: {Elapsed}", stopwatch.ElapsedMilliseconds);

// ❌ BAD: Logger passed as parameter (can't use [LoggerMessage])
private void DoWork(ILogger logger)
{
    logger.LogDebug("Working...");  // Can't use [LoggerMessage] here
}

// ✅ GOOD: Use [LoggerMessage] with instance logger
LogValidationStarted(thumbprint);
```

### When NOT to Use [LoggerMessage]

- Static methods where logger is passed as parameter
- Code that rarely logs (startup/shutdown code)
- Tests or example code where clarity is more important than performance

---

## Exit Codes

CoseSignTool uses consistent exit codes for automation:

| Code | Name | Description |
|------|------|-------------|
| 0 | Success | Operation completed successfully |
| 1 | InvalidArguments | Command-line argument parsing failed |
| 2 | ValidationFailed | Signature validation failed |
| 3 | SigningFailed | Signing operation failed |
| 4 | FileNotFound | Required file not found |
| 5 | CertificateError | Certificate loading or validation error |
| 99 | GeneralError | Unexpected error |

```bash
# Check exit code
cosesigntool verify document.cose -q
echo "Exit code: $?"
```
