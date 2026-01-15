// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin;

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSignTool.Abstractions;
using CoseSignTool.Abstractions.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Verification provider for X.509 certificate-based signature validation.
///
/// IMPORTANT: This provider is TrustPlan-only. It does not add legacy assertion providers.
/// Trust requirements (chain trust, subject/issuer matching, etc.) are enforced via
/// TrustPlanPolicy + trust fact producers (see X509VerificationProvider.TrustPolicy.cs).
/// </summary>
public partial class X509VerificationProvider : IVerificationProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ProviderName = "X509";
        public const string ProviderDescription = "X.509 certificate-based signature validation";

        public const string OptionNameTrustRoots = "--trust-roots";
        public const string OptionAliasTrustRoots = "--roots";
        public const string DescriptionTrustRoots = "One or more PEM/DER certificate files to treat as trust roots";

        public const string OptionNameTrustPfx = "--trust-pfx";
        public const string DescriptionTrustPfx = "PFX/PKCS#12 file containing one or more trust roots";

        public const string OptionNameTrustPfxPasswordFile = "--trust-pfx-password-file";
        public const string DescriptionTrustPfxPasswordFile = "Path to a file containing the PFX password (more secure than command-line). Alternatively, set COSESIGNTOOL_TRUST_PFX_PASSWORD environment variable.";

        public const string OptionNameTrustPfxPasswordEnv = "--trust-pfx-password-env";
        public const string DescriptionTrustPfxPasswordEnv = "Name of environment variable containing the PFX password (default: COSESIGNTOOL_TRUST_PFX_PASSWORD)";

        public const string DefaultTrustPfxPasswordEnvVar = "COSESIGNTOOL_TRUST_PFX_PASSWORD";

        public const string OptionNameTrustSystemRoots = "--trust-system-roots";
        public const string DescriptionTrustSystemRoots = "Use system trust roots for chain validation (default: true)";

        public const string OptionNameAllowUntrusted = "--allow-untrusted";
        public const string DescriptionAllowUntrusted = "Allow untrusted roots (skip chain trust requirement)";

        public const string OptionNameSubjectName = "--subject-name";
        public const string OptionAliasSubjectName = "--cn";
        public const string DescriptionSubjectName = "Require the signing certificate subject CN to match this value";

        public const string OptionNameIssuerName = "--issuer-name";
        public const string OptionAliasIssuerName = "--issuer";
        public const string DescriptionIssuerName = "Require the signing certificate issuer CN to match this value";

        public const string OptionNameRevocationMode = "--revocation-mode";
        public const string DescriptionRevocationMode = "Certificate revocation checking: online, offline, or none";

        public const string RevocationModeOnline = "online";
        public const string RevocationModeOffline = "offline";
        public const string RevocationModeNone = "none";

        public const string InfoReadingPasswordFile = "Reading PFX password from file: {Path}";
        public const string InfoUsingEnvPassword = "Using PFX password from environment variable: {Name}";

        public const string MetaKeyTrustMode = "Trust Mode";
        public const string MetaKeyRequiredSubject = "Required Subject CN";
        public const string MetaKeyRequiredIssuer = "Required Issuer CN";
        public const string MetaKeyRevocationCheck = "Revocation Check";

        public const string MetaValueSystemTrust = "System Trust";
        public const string MetaValueCustomRoots = "Custom Roots";
        public const string MetaValueUntrustedAllowed = "Allow Untrusted";

        public const string X509ChainMustBeTrusted = "X.509 chain must be trusted";
        public const string X509SubjectCommonNameMustMatch = "Certificate subject common name must match";
        public const string X509IssuerCommonNameMustMatch = "Certificate issuer common name must match";

        public const string X509SubjectCommonNameMustMatchFormat = "Certificate subject common name must match: {0}";
        public const string X509IssuerCommonNameMustMatchFormat = "Certificate issuer common name must match: {0}";

        public const string DistinguishedNameCnPrefix = "CN=";
    }

    /// <inheritdoc/>
    public string ProviderName => ClassStrings.ProviderName;

    /// <inheritdoc/>
    public string Description => ClassStrings.ProviderDescription;

    /// <inheritdoc/>
    public int Priority => 10;

    // Options stored as fields so other partials (TrustPolicy) can read them if needed.
    internal Option<FileInfo[]?> TrustRootsOption = null!;
    internal Option<FileInfo?> TrustPfxOption = null!;
    internal Option<FileInfo?> TrustPfxPasswordFileOption = null!;
    internal Option<string?> TrustPfxPasswordEnvOption = null!;
    internal Option<bool> TrustSystemRootsOption = null!;
    internal Option<bool> AllowUntrustedOption = null!;
    internal Option<string?> SubjectNameOption = null!;
    internal Option<string?> IssuerNameOption = null!;
    internal Option<string> RevocationModeOption = null!;

    /// <inheritdoc/>
    public void AddVerificationOptions(Command command)
    {
        TrustRootsOption = new Option<FileInfo[]?>(
            name: ClassStrings.OptionNameTrustRoots,
            description: ClassStrings.DescriptionTrustRoots)
        {
            Arity = ArgumentArity.ZeroOrMore
        };
        TrustRootsOption.AddAlias(ClassStrings.OptionAliasTrustRoots);
        command.AddOption(TrustRootsOption);

        TrustPfxOption = new Option<FileInfo?>(
            name: ClassStrings.OptionNameTrustPfx,
            description: ClassStrings.DescriptionTrustPfx);
        command.AddOption(TrustPfxOption);

        TrustPfxPasswordFileOption = new Option<FileInfo?>(
            name: ClassStrings.OptionNameTrustPfxPasswordFile,
            description: ClassStrings.DescriptionTrustPfxPasswordFile);
        command.AddOption(TrustPfxPasswordFileOption);

        TrustPfxPasswordEnvOption = new Option<string?>(
            name: ClassStrings.OptionNameTrustPfxPasswordEnv,
            description: ClassStrings.DescriptionTrustPfxPasswordEnv);
        command.AddOption(TrustPfxPasswordEnvOption);

        TrustSystemRootsOption = new Option<bool>(
            name: ClassStrings.OptionNameTrustSystemRoots,
            getDefaultValue: () => true,
            description: ClassStrings.DescriptionTrustSystemRoots);
        command.AddOption(TrustSystemRootsOption);

        AllowUntrustedOption = new Option<bool>(
            name: ClassStrings.OptionNameAllowUntrusted,
            description: ClassStrings.DescriptionAllowUntrusted);
        command.AddOption(AllowUntrustedOption);

        SubjectNameOption = new Option<string?>(
            name: ClassStrings.OptionNameSubjectName,
            description: ClassStrings.DescriptionSubjectName);
        SubjectNameOption.AddAlias(ClassStrings.OptionAliasSubjectName);
        command.AddOption(SubjectNameOption);

        IssuerNameOption = new Option<string?>(
            name: ClassStrings.OptionNameIssuerName,
            description: ClassStrings.DescriptionIssuerName);
        IssuerNameOption.AddAlias(ClassStrings.OptionAliasIssuerName);
        command.AddOption(IssuerNameOption);

        RevocationModeOption = new Option<string>(
            name: ClassStrings.OptionNameRevocationMode,
            getDefaultValue: () => ClassStrings.RevocationModeOnline,
            description: ClassStrings.DescriptionRevocationMode);
        RevocationModeOption.FromAmong(
            ClassStrings.RevocationModeOnline,
            ClassStrings.RevocationModeOffline,
            ClassStrings.RevocationModeNone);
        command.AddOption(RevocationModeOption);
    }

    /// <inheritdoc/>
    public bool IsActivated(ParseResult parseResult)
    {
        _ = parseResult;
        return true;
    }

    /// <inheritdoc/>
    public void ConfigureValidation(ICoseValidationBuilder validationBuilder, ParseResult parseResult, VerificationContext context)
    {
        ArgumentNullException.ThrowIfNull(validationBuilder);
        ArgumentNullException.ThrowIfNull(parseResult);
        ArgumentNullException.ThrowIfNull(context);

        // Trust is enforced via TrustPlanPolicy + facts; we enable the certificate trust pack here.
        var revocationMode = ParseRevocationMode(parseResult);
        var customRoots = HasCustomTrustRoots(parseResult)
            ? LoadCustomRoots(parseResult, NullLogger<X509VerificationProvider>.Instance)
            : null;

        validationBuilder.EnableCertificateTrust(certTrust =>
        {
            certTrust
                .WithRevocationMode(revocationMode);

            if (customRoots != null && customRoots.Count > 0)
            {
                certTrust.UseCustomRootTrust(customRoots);
            }
            else if (IsTrustSystemRoots(parseResult))
            {
                certTrust.UseSystemTrust();
            }
        });

        // Preserve historical CLI behavior: allow key material in unprotected headers.
        var loggerFactory = context.LoggerFactory ?? NullLoggerFactory.Instance;
        var logger = loggerFactory.CreateLogger<CertificateSigningKeyResolver>();
        validationBuilder.Services.AddSingleton<ISigningKeyResolver>(
            _ => new CertificateSigningKeyResolver(CoseHeaderLocation.Any, logger));
    }

    /// <inheritdoc/>
    public IDictionary<string, object?> GetVerificationMetadata(
        ParseResult parseResult,
        CoseSign1Message message,
        ValidationResult validationResult)
    {
        _ = message;
        _ = validationResult;

        var metadata = new Dictionary<string, object?>
        {
            [ClassStrings.MetaKeyTrustMode] = HasCustomTrustRoots(parseResult) ? ClassStrings.MetaValueCustomRoots :
                IsAllowUntrusted(parseResult) ? ClassStrings.MetaValueUntrustedAllowed :
                ClassStrings.MetaValueSystemTrust
        };

        var subject = GetSubjectName(parseResult);
        if (!string.IsNullOrEmpty(subject))
        {
            metadata[ClassStrings.MetaKeyRequiredSubject] = subject;
        }

        var issuer = GetIssuerName(parseResult);
        if (!string.IsNullOrEmpty(issuer))
        {
            metadata[ClassStrings.MetaKeyRequiredIssuer] = issuer;
        }

        metadata[ClassStrings.MetaKeyRevocationCheck] = ParseRevocationMode(parseResult).ToString();

        return metadata;
    }

    #region Helpers used by TrustPolicy partial

    internal bool HasCustomTrustRoots(ParseResult parseResult)
    {
        var roots = parseResult.GetValueForOption(TrustRootsOption);
        return (roots != null && roots.Length > 0) || HasTrustPfx(parseResult);
    }

    internal bool HasTrustPfx(ParseResult parseResult)
    {
        var pfx = parseResult.GetValueForOption(TrustPfxOption);
        return pfx?.Exists == true;
    }

    internal SecureString? GetTrustPfxPassword(ParseResult parseResult, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        if (!HasTrustPfx(parseResult))
        {
            return null;
        }

        var passwordFile = parseResult.GetValueForOption(TrustPfxPasswordFileOption);
        if (passwordFile?.Exists == true)
        {
            logger.LogInformation(ClassStrings.InfoReadingPasswordFile, passwordFile.FullName);
            return SecurePasswordProvider.ReadPasswordFromFile(passwordFile.FullName);
        }

        var customEnvVar = parseResult.GetValueForOption(TrustPfxPasswordEnvOption);
        var envVarName = string.IsNullOrEmpty(customEnvVar) ? ClassStrings.DefaultTrustPfxPasswordEnvVar : customEnvVar;
        var envPassword = Environment.GetEnvironmentVariable(envVarName);
        if (!string.IsNullOrEmpty(envPassword))
        {
            logger.LogInformation(ClassStrings.InfoUsingEnvPassword, envVarName);
            return SecurePasswordProvider.ConvertToSecureString(envPassword);
        }

        return null;
    }

    internal bool IsTrustSystemRoots(ParseResult parseResult) =>
        parseResult.GetValueForOption(TrustSystemRootsOption);

    internal bool IsAllowUntrusted(ParseResult parseResult) =>
        parseResult.GetValueForOption(AllowUntrustedOption);

    internal string? GetSubjectName(ParseResult parseResult) =>
        parseResult.GetValueForOption(SubjectNameOption);

    internal string? GetIssuerName(ParseResult parseResult) =>
        parseResult.GetValueForOption(IssuerNameOption);

    internal X509RevocationMode ParseRevocationMode(ParseResult parseResult)
    {
        var mode = parseResult.GetValueForOption(RevocationModeOption) ?? ClassStrings.RevocationModeOnline;
        return mode.ToLowerInvariant() switch
        {
            ClassStrings.RevocationModeOnline => X509RevocationMode.Online,
            ClassStrings.RevocationModeOffline => X509RevocationMode.Offline,
            ClassStrings.RevocationModeNone => X509RevocationMode.NoCheck,
            _ => X509RevocationMode.Online
        };
    }

    internal X509Certificate2Collection LoadCustomRoots(ParseResult parseResult, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        var collection = new X509Certificate2Collection();

        var roots = parseResult.GetValueForOption(TrustRootsOption);
        if (roots != null)
        {
            foreach (var rootFile in roots)
            {
                if (rootFile.Exists)
                {
                    try
                    {
                        collection.Add(X509CertificateLoader.LoadCertificateFromFile(rootFile.FullName));
                    }
                    catch
                    {
                    }
                }
            }
        }

        var pfxFile = parseResult.GetValueForOption(TrustPfxOption);
        if (pfxFile?.Exists == true)
        {
            try
            {
                var password = GetTrustPfxPassword(parseResult, logger);
                var passwordPlain = password != null ? SecurePasswordProvider.ConvertToPlainString(password) : null;

                var pfxCollection = X509CertificateLoader.LoadPkcs12CollectionFromFile(
                    pfxFile.FullName,
                    password: passwordPlain,
                    X509KeyStorageFlags.DefaultKeySet);

                collection.AddRange(pfxCollection);
            }
            catch
            {
            }
        }

        return collection;
    }

    #endregion

    internal static string? ExtractCommonName(string distinguishedName)
    {
        if (string.IsNullOrWhiteSpace(distinguishedName))
        {
            return null;
        }

        var parts = distinguishedName.Split(',');
        foreach (var part in parts)
        {
            var trimmedPart = part.Trim();
            if (trimmedPart.StartsWith(ClassStrings.DistinguishedNameCnPrefix, StringComparison.OrdinalIgnoreCase))
            {
                return trimmedPart.Substring(ClassStrings.DistinguishedNameCnPrefix.Length).Trim();
            }
        }

        return null;
    }
}
