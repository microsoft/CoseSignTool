# Azure Code Transparency Service Plugin

The Azure Code Transparency Service (CTS) plugin provides integration with Azure's Code Transparency Service for registering and verifying COSE Sign1 signatures. This plugin demonstrates advanced authentication patterns and service integration capabilities.

## Overview

The Azure CTS plugin (`CoseSignTool.CTS.Plugin`) extends CoseSignTool with commands to interact with Azure Code Transparency Service:

- `cts_register` - Register a COSE Sign1 signature with Azure CTS
- `cts_verify` - Verify a COSE Sign1 signature against Azure CTS

## Installation

The Azure CTS plugin is automatically included with CoseSignTool releases using the enhanced subdirectory architecture for dependency isolation. No additional installation is required.

**Plugin Location:** The plugin is deployed to `plugins/CoseSignTool.CTS.Plugin/` with all its Azure dependencies isolated in the subdirectory, preventing conflicts with other plugins or the main application.

## Authentication

The plugin supports flexible authentication methods with automatic fallback:

### 1. Environment Variable Authentication (Recommended)

Set an access token in an environment variable:

```bash
# Using the default environment variable
export AZURE_CTS_TOKEN="your-access-token"

# Using a custom environment variable
export MY_CTS_TOKEN="your-access-token"
```

### 2. Azure DefaultCredential (Fallback)

When no token is provided, the plugin automatically falls back to Azure DefaultCredential, which supports:
- Azure CLI credentials (`az login`)
- Managed Identity (in Azure environments)
- Azure PowerShell credentials
- Environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`)
- Visual Studio credentials
- VS Code credentials

> **⚠️ Production Security Note**: When deploying to production environments, create an environment variable named `AZURE_TOKEN_CREDENTIALS` and set its value to `"prod"`. This excludes developer tool credentials from the credential chain, ensuring only production-appropriate credentials are used. This is required when using Azure.Identity version 1.14.0 or later. For more information, see the [DefaultAzureCredential overview](https://docs.microsoft.com/en-us/dotnet/api/azure.identity.defaultazurecredential).

```bash
# In production environments, set this environment variable:
export AZURE_TOKEN_CREDENTIALS="prod"
```

## Commands

### cts_register

Register a COSE Sign1 signature with Azure Code Transparency Service.

#### Syntax
```bash
CoseSignTool cts_register [OPTIONS]
```

#### Required Options
- `--endpoint` - Azure CTS service endpoint URL
- `--payload` - Path to the payload file
- `--signature` - Path to the COSE Sign1 signature file

#### Optional Options
- `--token-env-var` - Environment variable name containing the access token (default: `AZURE_CTS_TOKEN`)
- `--output` - Output file path for the registration result
- `--timeout` - Operation timeout in seconds (default: 30)

#### Examples

**Using default environment variable:**
```bash
export AZURE_CTS_TOKEN="your-access-token"
CoseSignTool cts_register \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose
```

**Using custom environment variable:**
```bash
export MY_CTS_TOKEN="your-access-token"
CoseSignTool cts_register \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose \
    --token-env-var MY_CTS_TOKEN
```

**Using Azure DefaultCredential:**
```bash
# Requires az login or other Azure authentication
CoseSignTool cts_register \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose
```

**With output file:**
```bash
export AZURE_CTS_TOKEN="your-access-token"
CoseSignTool cts_register \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose \
    --output registration-result.json
```

### cts_verify

Verify a COSE Sign1 signature against Azure Code Transparency Service.

#### Syntax
```bash
CoseSignTool cts_verify [OPTIONS]
```

#### Required Options
- `--endpoint` - Azure CTS service endpoint URL
- `--payload` - Path to the payload file
- `--signature` - Path to the COSE Sign1 signature file

#### Optional Options
- `--token-env-var` - Environment variable name containing the access token (default: `AZURE_CTS_TOKEN`)
- `--output` - Output file path for the verification result
- `--receipt` - Path to save the transparency receipt
- `--timeout` - Operation timeout in seconds (default: 30)

#### Examples

**Basic verification:**
```bash
export AZURE_CTS_TOKEN="your-access-token"
CoseSignTool cts_verify \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose
```

**With receipt output:**
```bash
export AZURE_CTS_TOKEN="your-access-token"
CoseSignTool cts_verify \
    --endpoint https://your-cts-instance.azure.com \
    --payload myfile.txt \
    --signature myfile.txt.cose \
    --receipt transparency-receipt.json
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Sign and Register with Azure CTS

on:
  push:
    branches: [ main ]

jobs:
  sign-and-register:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup .NET
      uses: actions/setup-dotnet@v3
      with:
        dotnet-version: '8.0.x'
    
    - name: Install CoseSignTool
      run: |
        curl -L https://github.com/microsoft/CoseSignTool/releases/latest/download/CoseSignTool-Linux-release.zip -o CoseSignTool.zip
        unzip CoseSignTool.zip
        chmod +x CoseSignTool
    
    - name: Sign file
      run: |
        ./CoseSignTool sign \
          --payload myfile.txt \
          --p12-file ${{ secrets.SIGNING_CERT_P12 }} \
          --p12-password ${{ secrets.SIGNING_CERT_PASSWORD }} \
          --output myfile.txt.cose
    
    - name: Register with Azure CTS
      env:
        AZURE_CTS_TOKEN: ${{ secrets.AZURE_CTS_TOKEN }}
        AZURE_TOKEN_CREDENTIALS: "prod"  # Exclude developer credentials in production
      run: |
        ./CoseSignTool cts_register \
          --endpoint https://your-cts-instance.azure.com \
          --payload myfile.txt \
          --signature myfile.txt.cose
```

### Azure DevOps

```yaml
trigger:
- main

pool:
  vmImage: ubuntu-latest

variables:
  AZURE_CTS_TOKEN: $(azure-cts-token)  # Set in Azure DevOps Library
  AZURE_TOKEN_CREDENTIALS: "prod"  # Exclude developer credentials in production

steps:
- task: UseDotNet@2
  displayName: 'Use .NET 8.0'
  inputs:
    packageType: 'sdk'
    version: '8.0.x'

- bash: |
    curl -L https://github.com/microsoft/CoseSignTool/releases/latest/download/CoseSignTool-Linux-release.zip -o CoseSignTool.zip
    unzip CoseSignTool.zip
    chmod +x CoseSignTool
  displayName: 'Install CoseSignTool'

- bash: |
    ./CoseSignTool sign \
      --payload myfile.txt \
      --p12-file $(signing-cert-p12) \
      --p12-password $(signing-cert-password) \
      --output myfile.txt.cose
  displayName: 'Sign file'

- bash: |
    ./CoseSignTool cts_register \
      --endpoint https://your-cts-instance.azure.com \
      --payload myfile.txt \
      --signature myfile.txt.cose
  displayName: 'Register with Azure CTS'
```

## Best Practices

### Security

1. **Never hardcode tokens** - Always use environment variables or Azure credentials
2. **Use secure secret management** - Store tokens in Azure Key Vault, GitHub Secrets, or Azure DevOps Library
3. **Rotate tokens regularly** - Implement token rotation policies
4. **Use managed identities** - When running in Azure, prefer managed identities over access tokens
5. **Production DefaultAzureCredential configuration** - In production environments, set `AZURE_TOKEN_CREDENTIALS="prod"` to exclude developer tool credentials from the credential chain. This is required when using Azure.Identity version 1.14.0 or later for security compliance.

### Performance

1. **Set appropriate timeouts** - Use `--timeout` for long-running operations
2. **Batch operations** - When possible, batch multiple operations to reduce authentication overhead
3. **Monitor usage** - Track API calls and response times for capacity planning

### Error Handling

The plugin returns specific exit codes for different scenarios:
- `0` - Success
- `1` - Generic error
- `2` - Missing required option
- `3` - Invalid argument value
- `4` - User-specified file not found
- `5` - Authentication failed
- `6` - Network/service error

## Troubleshooting

### Common Issues

**Authentication Failed:**
```
Error: Azure.Identity.CredentialUnavailableException: DefaultAzureCredential failed to retrieve a token
```
- Ensure `AZURE_CTS_TOKEN` is set, or authenticate with Azure CLI (`az login`)
- Check that the token has appropriate permissions for the CTS service

**Connection Timeout:**
```
Error: The operation timed out after 30 seconds
```
- Increase timeout with `--timeout 60`
- Check network connectivity to the Azure CTS endpoint

**Invalid Endpoint:**
```
Error: The endpoint URL is not valid
```
- Verify the endpoint URL format: `https://your-cts-instance.azure.com`
- Ensure the CTS service is accessible from your network

**Production Authentication Issues:**
```
Error: DefaultAzureCredential used developer credentials in production
```
- Set `AZURE_TOKEN_CREDENTIALS="prod"` to exclude developer tool credentials
- Ensure proper production authentication is configured (managed identity, service principal, etc.)
- Review authentication chain in logs to verify correct credential type is used

### Debug Mode

Enable verbose logging by setting environment variable:
```bash
export AZURE_CORE_DIAGNOSTICS_LOGGING_ENABLED=true
```

## Developer Information

### Plugin Architecture

The Azure CTS plugin is built using:
- **CoseSignTool.Abstractions** - Base plugin interfaces
- **Azure.Identity** - Azure authentication library
- **Azure.Core** - Azure SDK core functionality
- **System.Text.Json** - JSON serialization

### Source Code

The plugin source code is available in the CoseSignTool repository:
```
CoseSignTool.CTS.Plugin/
├── AzureCtsPlugin.cs              # Main plugin class
├── CtsCommandBase.cs              # Base command functionality
├── RegisterCommand.cs             # Register command implementation
├── VerifyCommand.cs              # Verify command implementation
├── CodeTransparencyClientHelper.cs # Authentication helper
└── CoseSignTool.CTS.Plugin.csproj
```

### Contributing

To contribute to the Azure CTS plugin:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Update documentation
6. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Support

For issues and questions:
- **Plugin Issues**: [GitHub Issues](https://github.com/microsoft/CoseSignTool/issues)
- **Azure CTS Service**: Azure support channels
- **Documentation**: [CoseSignTool Documentation](https://github.com/microsoft/CoseSignTool/tree/main/docs)

## License

This plugin is licensed under the MIT License. See [LICENSE](../LICENSE) for details.
