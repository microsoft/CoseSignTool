# CoseSignTool V2 CLI - Design Document

## Vision

Create a **modern, high-performance, extensible CLI** that leverages V2 libraries with:
- **Command pipelining** support (stdin/stdout)
- **Plugin extensibility** (certificate providers, signing services, validators)
- **Performance optimizations** (streaming, parallel processing, minimal allocations)
- **Delightful UX** (progress bars, colored output, interactive prompts, command completion)
- **Modern CLI patterns** (System.CommandLine, configuration files, environment variables)

## Architecture

### Core Principles

1. **Leverage V2 Libraries**: Use `CoseSign1.*` V2 packages exclusively
2. **Dependency Injection**: Service-based architecture with DI container
3. **Plugin-First**: Everything extensible through plugins
4. **Performance**: Streaming I/O, async/await, minimal allocations
5. **Standards**: Follow .NET CLI conventions and patterns

### Technology Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI Layer                                │
│  - System.CommandLine (command parsing)                    │
│  - Spectre.Console (rich output, progress, prompts)        │
│  - Microsoft.Extensions.Hosting (DI, configuration)         │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                  Plugin System                              │
│  - PluginLoader (discovery & loading)                      │
│  - ICertificateProviderPlugin (custom cert sources)        │
│  - ISigningServicePlugin (remote signing)                  │
│  - IValidatorPlugin (custom validation)                    │
│  - IOutputFormatterPlugin (custom output formats)          │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                  V2 Libraries                               │
│  - CoseSign1 (factories)                                   │
│  - CoseSign1.Certificates (certificate signing)            │
│  - CoseSign1.Validation (validation framework)             │
│  - CoseSign1.Headers (CWT claims, SCITT)                   │
│  - CoseSign1.Transparent.* (transparency services)         │
└─────────────────────────────────────────────────────────────┘
```

## Command Structure

### Top-Level Commands

```bash
cosesigntool [command] [options]

Commands:
  sign          Sign files with COSE Sign1
  verify        Verify COSE Sign1 signatures
  inspect       Inspect COSE Sign1 message structure
  extract       Extract payload from embedded signatures
  batch         Batch sign/verify multiple files
  config        Manage configuration and plugins
  completion    Generate shell completion scripts
```

### Command Examples

#### Sign Command
```bash
# Basic signing
cosesigntool sign input.bin -o output.cose --cert mycert.pfx

# Pipe support (read from stdin, write to stdout)
cat input.bin | cosesigntool sign --cert mycert.pfx > output.cose

# Batch signing with glob patterns
cosesigntool sign *.dll -o signed/ --cert mycert.pfx --parallel

# Remote signing (Azure Trusted Signing)
cosesigntool sign input.bin --provider azure-trusted-signing \
  --endpoint https://account.codesigning.azure.net \
  --account myaccount --profile myprofile

# SCITT-compliant attestation
cosesigntool sign artifact.tar.gz --scitt \
  --issuer "https://build.contoso.com" \
  --subject "pkg:npm/express@4.18.2"

# Detached signature
cosesigntool sign input.bin --signature-type detached -o input.cose

# Indirect signature (hash-based)
cosesigntool sign large-file.iso --signature-type indirect -o large-file.cose

# With transparency receipt
cosesigntool sign input.bin --transparency mst \
  --mst-endpoint https://transparency.contoso.com
```

#### Verify Command
```bash
# Basic verification
cosesigntool verify signature.cose

# Detached signature verification
cosesigntool verify signature.cose --payload original.bin

# Pipe support
cat signature.cose | cosesigntool verify --payload original.bin

# Custom validation rules
cosesigntool verify signature.cose \
  --require-eku 1.3.6.1.5.5.7.3.3 \
  --require-cn "MyTrustedSigner" \
  --check-expiration

# Batch verification
cosesigntool verify *.cose --parallel --summary

# Transparency receipt verification
cosesigntool verify signature.cose --verify-transparency
```

#### Inspect Command
```bash
# Show message structure
cosesigntool inspect signature.cose

# JSON output for automation
cosesigntool inspect signature.cose --format json

# Show certificate details
cosesigntool inspect signature.cose --show-certs

# Show headers
cosesigntool inspect signature.cose --show-headers
```

#### Batch Command
```bash
# Sign multiple files
cosesigntool batch sign --files *.dll --cert mycert.pfx

# Parallel processing with progress
cosesigntool batch sign --files "**/*.exe" --cert mycert.pfx \
  --parallel --max-degree 8 --progress

# Verify multiple files with summary report
cosesigntool batch verify --files *.cose --summary report.json
```

## Plugin System

### Plugin Types

#### 1. Certificate Provider Plugins
```csharp
public interface ICertificateProviderPlugin
{
    string Name { get; }
    string Description { get; }
    
    Task<ISigningService> CreateSigningServiceAsync(
        PluginContext context,
        CancellationToken cancellationToken = default);
    
    IEnumerable<PluginOption> GetOptions();
}
```

**Built-in Providers:**
- `local-pfx` - PFX file certificates
- `local-store` - Windows/Linux certificate stores
- `azure-trusted-signing` - Azure Trusted Signing
- `azure-key-vault` - Azure Key Vault (future)
- `pkcs11` - Hardware security modules (future)

#### 2. Validator Plugins
```csharp
public interface IValidatorPlugin
{
    string Name { get; }
    
    IValidator<CoseSign1Message> CreateValidator(
        PluginContext context);
    
    IEnumerable<PluginOption> GetOptions();
}
```

#### 3. Output Formatter Plugins
```csharp
public interface IOutputFormatterPlugin
{
    string Name { get; }
    string[] SupportedFormats { get; }
    
    Task FormatAsync(
        CoseSign1Message message,
        Stream output,
        PluginContext context,
        CancellationToken cancellationToken = default);
}
```

### Plugin Discovery

```
~/.cosesigntool/plugins/
├── azure-trusted-signing/
│   ├── AzureTrustedSigning.Plugin.dll
│   └── plugin.json
├── custom-validator/
│   ├── CustomValidator.Plugin.dll
│   └── plugin.json
└── ...
```

**plugin.json:**
```json
{
  "name": "azure-trusted-signing",
  "version": "2.0.0",
  "author": "Microsoft",
  "description": "Azure Trusted Signing certificate provider",
  "type": "CertificateProvider",
  "assembly": "AzureTrustedSigning.Plugin.dll",
  "entryPoint": "AzureTrustedSigning.Plugin.AzureTrustedSigningPlugin"
}
```

## Performance Optimizations

### 1. Streaming I/O
- Stream large files without loading into memory
- Support stdin/stdout for pipeline integration
- Async I/O throughout

### 2. Parallel Processing
```bash
# Process multiple files in parallel
cosesigntool batch sign --files *.dll --parallel --max-degree 8
```

### 3. Minimal Allocations
- Use `Span<T>` and `Memory<T>` for data manipulation
- ArrayPool for temporary buffers
- String interning for repeated strings

### 4. Progress Reporting
```csharp
// Using Spectre.Console for rich progress
await AnsiConsole.Progress()
    .StartAsync(async ctx =>
    {
        var task = ctx.AddTask("Signing files...");
        // Process with progress updates
    });
```

## Configuration

### Configuration File
```yaml
# ~/.cosesigntool/config.yaml
defaults:
  cert-provider: local-pfx
  output-format: binary
  parallel-degree: 4
  
certificate-providers:
  azure-trusted-signing:
    endpoint: https://myaccount.codesigning.azure.net
    account: myaccount
    profile: production
    
validation:
  require-expiration-check: true
  require-chain-trust: true
  
output:
  colored: true
  progress: true
  verbose: false
```

### Environment Variables
```bash
COSESIGNTOOL_CERT_PROVIDER=azure-trusted-signing
COSESIGNTOOL_PARALLEL_DEGREE=8
COSESIGNTOOL_CONFIG_PATH=~/.cosesigntool/config.yaml
```

## User Experience Enhancements

### 1. Colored Output (Spectre.Console)
```
✓ Signature verified successfully
  Certificate: CN=Microsoft Corporation
  Issued by: CN=Microsoft Code Signing PCA 2011
  Valid from: 2024-01-01 to 2025-01-01
  
✗ Validation failed
  × Signature verification failed
  × Certificate expired (2024-12-01)
```

### 2. Progress Bars
```
Signing 1,247 files...
[━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━] 100% (1247/1247) 
  Completed: 1,245 | Failed: 2 | Duration: 45.2s
```

### 3. Interactive Prompts
```bash
$ cosesigntool sign input.bin
? Select certificate provider:
  > Local PFX File
    Windows Certificate Store
    Azure Trusted Signing
    
? PFX file path: mycert.pfx
? Password: ********
✓ Signature created: output.cose
```

### 4. Shell Completion
```bash
# Generate completion scripts
cosesigntool completion bash > cosesigntool-completion.bash
cosesigntool completion powershell > cosesigntool-completion.ps1
```

## Error Handling

### Structured Error Codes
```csharp
public enum ExitCode
{
    Success = 0,
    GeneralError = 1,
    InvalidArguments = 2,
    FileNotFound = 3,
    CertificateNotFound = 4,
    SigningFailed = 10,
    ValidationFailed = 20,
    InvalidSignature = 21,
    CertificateExpired = 22,
    UntrustedCertificate = 23,
    PluginError = 30
}
```

### User-Friendly Error Messages
```
Error: Certificate not found (Exit code: 4)
  
Could not find certificate with thumbprint: ABC123...
  
Suggestions:
  • Check that the certificate is installed in the correct store
  • Verify the thumbprint is correct
  • Try specifying --store-location and --store-name explicitly
  
For more help: cosesigntool help sign
```

## Implementation Plan

### Phase 1: Core Infrastructure (Week 1-2)
- ✅ Project setup (System.CommandLine, Spectre.Console, DI)
- ✅ Basic command structure (sign, verify, inspect)
- ✅ Configuration system (YAML, environment variables)
- ✅ Plugin loader infrastructure

### Phase 2: Core Commands (Week 3-4)
- ✅ Sign command with local certificates
- ✅ Verify command with basic validation
- ✅ Inspect command with rich output
- ✅ Extract command for embedded payloads

### Phase 3: Advanced Features (Week 5-6)
- ✅ Batch command with parallel processing
- ✅ Streaming I/O support
- ✅ Progress bars and colored output
- ✅ Interactive prompts

### Phase 4: Plugin System (Week 7-8)
- ✅ Certificate provider plugins
- ✅ Validator plugins
- ✅ Output formatter plugins
- ✅ Built-in plugins (Azure Trusted Signing, etc.)

### Phase 5: Polish & Documentation (Week 9-10)
- ✅ Shell completion
- ✅ Comprehensive documentation
- ✅ Performance testing and optimization
- ✅ User testing and feedback

## Testing Strategy

### Unit Tests
- Command handlers
- Plugin loaders
- Configuration parsing
- Validators

### Integration Tests
- End-to-end command execution
- Plugin loading and execution
- Pipeline integration (stdin/stdout)

### Performance Tests
- Large file signing
- Batch processing benchmarks
- Memory profiling
- Parallel processing scalability

## Success Metrics

- **Performance**: Sign 1000 files in < 60 seconds
- **Memory**: < 100MB for typical operations
- **Startup**: < 500ms cold start time
- **User Satisfaction**: 90%+ positive feedback
- **Plugin Ecosystem**: 5+ community plugins within 6 months

## Future Enhancements

- **Watch mode**: `cosesigntool watch --path ./dist --auto-sign`
- **REST API mode**: `cosesigntool serve --port 8080`
- **VS Code extension**: Integration with VS Code
- **GitHub Actions**: Official actions for CI/CD
- **Container images**: Docker images for easy deployment
- **Web UI**: Optional web interface for visual operations
