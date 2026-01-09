// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin;

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using CoseSign1.Abstractions;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Local;
using CoseSignTool.Abstractions;
using CoseSignTool.Abstractions.Security;
using Microsoft.Extensions.Logging;

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
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Command metadata
        public static readonly string CommandNameValue = "sign-pfx";
        public static readonly string CommandDescriptionValue = "Sign a payload with a PFX/PKCS#12 certificate file";
        public static readonly string ExampleUsageValue = "--pfx cert.pfx";

        // Option names
        public static readonly string OptionNamePfx = "--pfx";
        public static readonly string OptionNamePfxPasswordFile = "--pfx-password-file";
        public static readonly string OptionNamePfxPasswordEnv = "--pfx-password-env";
        public static readonly string OptionNamePfxPasswordPrompt = "--pfx-password-prompt";

        // Option descriptions
        public static readonly string DescriptionPfx = "Path to PFX/PKCS#12 file containing the signing certificate";
        public static readonly string DescriptionPfxPasswordFile = string.Concat(
            "Path to a file containing the PFX password (more secure than command-line). ",
            "Alternatively, set COSESIGNTOOL_PFX_PASSWORD environment variable.");
        public static readonly string DescriptionPfxPasswordEnv =
            "Name of environment variable containing the PFX password (default: COSESIGNTOOL_PFX_PASSWORD)";
        public static readonly string DescriptionPfxPasswordPrompt =
            "Prompt for password interactively (automatic if no password is provided)";

        // Dictionary keys (internal)
        public static readonly string KeyPfx = "pfx";
        public static readonly string KeyPfxPasswordEnv = "pfx-password-env";
        public static readonly string KeyPfxPasswordFile = "pfx-password-file";
        public static readonly string KeyPfxPasswordPrompt = "pfx-password-prompt";
        public static readonly string KeyLoggerFactory = "__loggerFactory";

        // Error messages
        public static readonly string ErrorPfxRequired = "PFX file is required";
        public static readonly string ErrorPfxNotFound = "PFX file not found: {0}";

        // Info messages
        public static readonly string InfoUsingEnvPassword = "Using PFX password from environment variable: {0}";
        public static readonly string InfoReadingPasswordFile = "Reading PFX password from file: {0}";
        public static readonly string PromptEnterPassword = "Enter PFX password: ";

        // Metadata keys and values
        public static readonly string MetaKeyCertSource = "Certificate Source";
        public static readonly string MetaKeyCertSubject = "Certificate Subject";
        public static readonly string MetaKeyCertThumbprint = "Certificate Thumbprint";
        public static readonly string MetaValuePfxFile = "PFX file";
        public static readonly string MetaValueUnknown = "Unknown";
    }

    private ISigningService<CoseSign1.Abstractions.SigningOptions>? SigningService;
    private string? CertificateSubject;
    private string? CertificateThumbprint;

    /// <inheritdoc/>
    public string CommandName => ClassStrings.CommandNameValue;

    /// <inheritdoc/>
    public string CommandDescription => ClassStrings.CommandDescriptionValue;

    /// <inheritdoc/>
    public string ExampleUsage => ClassStrings.ExampleUsageValue;

    /// <inheritdoc/>
    public void AddCommandOptions(Command command)
    {
        var pfxOption = new Option<FileInfo>(
            name: ClassStrings.OptionNamePfx,
            description: ClassStrings.DescriptionPfx)
        {
            IsRequired = true
        };

        var pfxPasswordFileOption = new Option<FileInfo?>(
            name: ClassStrings.OptionNamePfxPasswordFile,
            description: ClassStrings.DescriptionPfxPasswordFile);

        var pfxPasswordEnvVarOption = new Option<string?>(
            name: ClassStrings.OptionNamePfxPasswordEnv,
            description: ClassStrings.DescriptionPfxPasswordEnv);

        var pfxPasswordPromptOption = new Option<bool>(
            name: ClassStrings.OptionNamePfxPasswordPrompt,
            description: ClassStrings.DescriptionPfxPasswordPrompt);

        command.AddOption(pfxOption);
        command.AddOption(pfxPasswordFileOption);
        command.AddOption(pfxPasswordEnvVarOption);
        command.AddOption(pfxPasswordPromptOption);
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Required options are missing.</exception>
    /// <exception cref="FileNotFoundException">The PFX file does not exist.</exception>
    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
    {
        var pfxFile = options[ClassStrings.KeyPfx] as FileInfo
            ?? throw new InvalidOperationException(ClassStrings.ErrorPfxRequired);

        // Get logger factory if provided
        var loggerFactory = options.TryGetValue(ClassStrings.KeyLoggerFactory, out var lf) ? lf as ILoggerFactory : null;
        var logger = loggerFactory?.CreateLogger<PfxCertificateSource>();

        if (!pfxFile.Exists)
        {
            throw new FileNotFoundException(string.Format(ClassStrings.ErrorPfxNotFound, pfxFile.FullName));
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
        var signingServiceLogger = loggerFactory?.CreateLogger<CertificateSigningService>();

        // Create and return signing service
        SigningService = CertificateSigningService.Create(signingCert, chainBuilder, signingServiceLogger);

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
        var loggerFactory = options.TryGetValue(ClassStrings.KeyLoggerFactory, out var lf) ? lf as ILoggerFactory : null;
        var logger = loggerFactory?.CreateLogger<PfxSigningCommandProvider>();

        // Check for custom environment variable name
        var envVarName = options.TryGetValue(ClassStrings.KeyPfxPasswordEnv, out var envName) && envName is string customEnvVar
            ? customEnvVar
            : SecurePasswordProvider.DefaultPfxPasswordEnvVar;

        // 1. Try environment variable first
        var envPassword = SecurePasswordProvider.GetPasswordFromEnvironment(envVarName);
        if (envPassword != null)
        {
            logger?.LogInformation(ClassStrings.InfoUsingEnvPassword, envVarName);
            return envPassword;
        }

        // 2. Try password file
        var passwordFile = options.TryGetValue(ClassStrings.KeyPfxPasswordFile, out var pwdFile) ? pwdFile as FileInfo : null;
        if (passwordFile?.Exists == true)
        {
            logger?.LogInformation(ClassStrings.InfoReadingPasswordFile, passwordFile.FullName);
            return SecurePasswordProvider.ReadPasswordFromFile(passwordFile.FullName);
        }

        // 3. Check if explicit prompt requested or if interactive input is available
        var promptRequested = options.TryGetValue(ClassStrings.KeyPfxPasswordPrompt, out var prompt) && prompt is true;
        var passwordProvider = SecurePasswordProvider.Default;

        if (promptRequested || passwordProvider.IsInteractiveInputAvailable())
        {
            // Only prompt if explicitly requested or if we're interactive
            if (promptRequested)
            {
                return passwordProvider.ReadPasswordFromConsole(ClassStrings.PromptEnterPassword);
            }

            // For non-prompted case, assume unprotected PFX (silent operation)
            return null;
        }

        // No password available - assume unprotected PFX
        return null;
    }

    /// <inheritdoc/>
    public IDictionary<string, string> GetSigningMetadata()
    {
        return new Dictionary<string, string>
        {
            [ClassStrings.MetaKeyCertSource] = ClassStrings.MetaValuePfxFile,
            [ClassStrings.MetaKeyCertSubject] = CertificateSubject ?? ClassStrings.MetaValueUnknown,
            [ClassStrings.MetaKeyCertThumbprint] = CertificateThumbprint ?? ClassStrings.MetaValueUnknown
        };
    }
}