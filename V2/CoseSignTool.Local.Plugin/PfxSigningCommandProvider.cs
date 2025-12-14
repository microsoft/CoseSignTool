// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.Security;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Local;
using CoseSignTool.Abstractions;
using CoseSignTool.Abstractions.Security;
using Microsoft.Extensions.Logging;

namespace CoseSignTool.Local.Plugin;

/// <summary>
/// Command provider for signing with PFX/PKCS#12 certificate files.
/// </summary>
/// <remarks>
/// <para>
/// <b>Security Best Practice:</b> The PFX password should NOT be passed directly on the command line,
/// as command-line arguments are often logged in shell history, process lists, and audit logs.
/// </para>
/// <para>
/// Supported password input methods (in order of precedence):
/// <list type="number">
/// <item><description>Environment variable: <c>COSESIGNTOOL_PFX_PASSWORD</c></description></item>
/// <item><description>Password file: <c>--pfx-password-file path/to/password.txt</c></description></item>
/// <item><description>Interactive prompt: Automatically triggered if no other method is used</description></item>
/// </list>
/// </para>
/// </remarks>
public class PfxSigningCommandProvider : ISigningCommandProvider
{
    private ISigningService<CoseSign1.Abstractions.SigningOptions>? SigningService;
    private string? CertificateSubject;
    private string? CertificateThumbprint;

    public string CommandName => "sign-pfx";

    public string CommandDescription => "Sign a payload with a PFX/PKCS#12 certificate file";

    public string ExampleUsage => "--pfx cert.pfx";

    public void AddCommandOptions(Command command)
    {
        var pfxOption = new Option<FileInfo>(
            name: "--pfx",
            description: "Path to PFX/PKCS#12 file containing the signing certificate")
        {
            IsRequired = true
        };

        var pfxPasswordFileOption = new Option<FileInfo?>(
            name: "--pfx-password-file",
            description: "Path to a file containing the PFX password (more secure than command-line). " +
                         "Alternatively, set COSESIGNTOOL_PFX_PASSWORD environment variable.");

        var pfxPasswordEnvVarOption = new Option<string?>(
            name: "--pfx-password-env",
            description: "Name of environment variable containing the PFX password (default: COSESIGNTOOL_PFX_PASSWORD)");

        var pfxPasswordPromptOption = new Option<bool>(
            name: "--pfx-password-prompt",
            description: "Prompt for password interactively (automatic if no password is provided)");

        command.AddOption(pfxOption);
        command.AddOption(pfxPasswordFileOption);
        command.AddOption(pfxPasswordEnvVarOption);
        command.AddOption(pfxPasswordPromptOption);
    }

    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        var pfxFile = options["pfx"] as FileInfo
            ?? throw new InvalidOperationException("PFX file is required");

        // Get logger factory if provided
        var loggerFactory = options.TryGetValue("__loggerFactory", out var lf) ? lf as ILoggerFactory : null;
        var logger = loggerFactory?.CreateLogger<PfxCertificateSource>();

        if (!pfxFile.Exists)
        {
            throw new FileNotFoundException($"PFX file not found: {pfxFile.FullName}");
        }

        // Get password using secure methods
        SecureString? pfxPassword = GetSecurePassword(options);

        // Create certificate source with secure password
        var certSource = new PfxCertificateSource(pfxFile.FullName, pfxPassword, logger: logger);
        var signingCert = certSource.GetSigningCertificate();
        var chainBuilder = certSource.GetChainBuilder();

        // Store metadata for later display
        CertificateSubject = signingCert.Subject;
        CertificateThumbprint = signingCert.Thumbprint;

        // Create logger for signing service
        var signingServiceLogger = loggerFactory?.CreateLogger<LocalCertificateSigningService>();

        // Create and return signing service
        SigningService = new LocalCertificateSigningService(signingCert, chainBuilder, signingServiceLogger);

        return await Task.FromResult(SigningService);
    }

    /// <summary>
    /// Gets the password using secure methods in order of precedence:
    /// 1. Environment variable (custom name via --pfx-password-env, or default COSESIGNTOOL_PFX_PASSWORD)
    /// 2. Password file (via --pfx-password-file)
    /// 3. Interactive prompt (if --pfx-password-prompt or no password found and console is available)
    /// </summary>
    private static SecureString? GetSecurePassword(IDictionary<string, object?> options)
    {
        // Check for custom environment variable name
        var envVarName = options.TryGetValue("pfx-password-env", out var envName) && envName is string customEnvVar
            ? customEnvVar
            : SecurePasswordProvider.DefaultPfxPasswordEnvVar;

        // 1. Try environment variable first
        var envPassword = SecurePasswordProvider.GetPasswordFromEnvironment(envVarName);
        if (envPassword != null)
        {
            Console.Error.WriteLine($"Using PFX password from environment variable: {envVarName}");
            return envPassword;
        }

        // 2. Try password file
        var passwordFile = options.TryGetValue("pfx-password-file", out var pwdFile) ? pwdFile as FileInfo : null;
        if (passwordFile?.Exists == true)
        {
            Console.Error.WriteLine($"Reading PFX password from file: {passwordFile.FullName}");
            return SecurePasswordProvider.ReadPasswordFromFile(passwordFile.FullName);
        }

        // 3. Check if explicit prompt requested or if interactive input is available
        var promptRequested = options.TryGetValue("pfx-password-prompt", out var prompt) && prompt is true;

        if (promptRequested || SecurePasswordProvider.IsInteractiveInputAvailable())
        {
            // Only prompt if explicitly requested or if we're interactive
            if (promptRequested)
            {
                return SecurePasswordProvider.ReadPasswordFromConsole("Enter PFX password: ");
            }

            // For non-prompted case, assume unprotected PFX (silent operation)
            return null;
        }

        // No password available - assume unprotected PFX
        return null;
    }

    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            ["Certificate Source"] = "PFX file",
            ["Certificate Subject"] = CertificateSubject ?? "Unknown",
            ["Certificate Thumbprint"] = CertificateThumbprint ?? "Unknown"
        };
    }
}