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
public partial class X509VerificationProvider : IVerificationProvider, IVerificationRootProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string RootId = "x509";

        public const string RootHelpSummary = "Verify using X.509 certificate trust";

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

    /// <inheritdoc/>
    public string RootId => ClassStrings.RootId;

    private static Option<T>? FindOption<T>(ParseResult parseResult, string optionToken)
    {
        var normalized = optionToken.TrimStart('-');

        for (var current = parseResult.CommandResult; current != null; current = current.Parent as CommandResult)
        {
            foreach (var opt in current.Command.Options)
            {
                if (string.Equals(opt.Name, normalized, StringComparison.OrdinalIgnoreCase))
                {
                    return opt as Option<T>;
                }

                foreach (var alias in opt.Aliases)
                {
                    if (string.Equals(alias.TrimStart('-'), normalized, StringComparison.OrdinalIgnoreCase))
                    {
                        return opt as Option<T>;
                    }
                }
            }
        }

        return null;
    }

    /// <inheritdoc/>
    public string RootDisplayName => ProviderName;

    /// <inheritdoc/>
    public string RootHelpSummary => ClassStrings.RootHelpSummary;

    /// <inheritdoc/>
    public void AddVerificationOptions(Command command)
    {
        var trustRootsOption = new Option<FileInfo[]?>(
            name: ClassStrings.OptionNameTrustRoots,
            description: ClassStrings.DescriptionTrustRoots)
        {
            Arity = ArgumentArity.ZeroOrMore
        };
        trustRootsOption.AddAlias(ClassStrings.OptionAliasTrustRoots);
        command.AddOption(trustRootsOption);

        var trustPfxOption = new Option<FileInfo?>(
            name: ClassStrings.OptionNameTrustPfx,
            description: ClassStrings.DescriptionTrustPfx);
        command.AddOption(trustPfxOption);

        var trustPfxPasswordFileOption = new Option<FileInfo?>(
            name: ClassStrings.OptionNameTrustPfxPasswordFile,
            description: ClassStrings.DescriptionTrustPfxPasswordFile);
        command.AddOption(trustPfxPasswordFileOption);

        var trustPfxPasswordEnvOption = new Option<string?>(
            name: ClassStrings.OptionNameTrustPfxPasswordEnv,
            description: ClassStrings.DescriptionTrustPfxPasswordEnv);
        command.AddOption(trustPfxPasswordEnvOption);

        var trustSystemRootsOption = new Option<bool>(
            name: ClassStrings.OptionNameTrustSystemRoots,
            getDefaultValue: () => true,
            description: ClassStrings.DescriptionTrustSystemRoots);
        command.AddOption(trustSystemRootsOption);

        var allowUntrustedOption = new Option<bool>(
            name: ClassStrings.OptionNameAllowUntrusted,
            description: ClassStrings.DescriptionAllowUntrusted);
        command.AddOption(allowUntrustedOption);

        var subjectNameOption = new Option<string?>(
            name: ClassStrings.OptionNameSubjectName,
            description: ClassStrings.DescriptionSubjectName);
        subjectNameOption.AddAlias(ClassStrings.OptionAliasSubjectName);
        command.AddOption(subjectNameOption);

        var issuerNameOption = new Option<string?>(
            name: ClassStrings.OptionNameIssuerName,
            description: ClassStrings.DescriptionIssuerName);
        issuerNameOption.AddAlias(ClassStrings.OptionAliasIssuerName);
        command.AddOption(issuerNameOption);

        var revocationModeOption = new Option<string>(
            name: ClassStrings.OptionNameRevocationMode,
            getDefaultValue: () => ClassStrings.RevocationModeOnline,
            description: ClassStrings.DescriptionRevocationMode);
        revocationModeOption.FromAmong(
            ClassStrings.RevocationModeOnline,
            ClassStrings.RevocationModeOffline,
            ClassStrings.RevocationModeNone);
        command.AddOption(revocationModeOption);
    }

    /// <inheritdoc/>
    public bool IsActivated(ParseResult parseResult)
    {
        ArgumentNullException.ThrowIfNull(parseResult);

        // X.509 is the default root trust model, but it should not be implicitly active when another
        // root trust model (e.g., MST receipt trust) is selected.
        //
        // The CLI host may still force-activate X509 as the default root provider; this method
        // answers a narrower question: did the user explicitly request X.509-specific behavior?

        if (HasCustomTrustRoots(parseResult))
        {
            return true;
        }

        var trustPfxOption = FindOption<FileInfo?>(parseResult, ClassStrings.OptionNameTrustPfx);
        if (trustPfxOption != null && parseResult.GetValueForOption(trustPfxOption) != null)
        {
            return true;
        }

        var trustPfxPasswordFileOption = FindOption<FileInfo?>(parseResult, ClassStrings.OptionNameTrustPfxPasswordFile);
        if (trustPfxPasswordFileOption != null && parseResult.GetValueForOption(trustPfxPasswordFileOption) != null)
        {
            return true;
        }

        var trustPfxPasswordEnvOption = FindOption<string?>(parseResult, ClassStrings.OptionNameTrustPfxPasswordEnv);
        var trustPfxPasswordEnv = trustPfxPasswordEnvOption != null ? parseResult.GetValueForOption(trustPfxPasswordEnvOption) : null;
        if (!string.IsNullOrWhiteSpace(trustPfxPasswordEnv))
        {
            return true;
        }

        if (IsAllowUntrusted(parseResult))
        {
            return true;
        }

        if (!IsTrustSystemRoots(parseResult))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(GetSubjectName(parseResult)))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(GetIssuerName(parseResult)))
        {
            return true;
        }

        var revocationModeOption = FindOption<string>(parseResult, ClassStrings.OptionNameRevocationMode);
        var revocationMode = revocationModeOption != null
            ? parseResult.GetValueForOption(revocationModeOption)
            : ClassStrings.RevocationModeOnline;
        if (!string.Equals(revocationMode, ClassStrings.RevocationModeOnline, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
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

        Microsoft.Extensions.DependencyInjection.CertificateSupportValidationBuilderExtensions.EnableCertificateSupport(validationBuilder, certTrust =>
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
        var trustRootsOption = FindOption<FileInfo[]?>(parseResult, ClassStrings.OptionNameTrustRoots);
        var roots = trustRootsOption != null ? parseResult.GetValueForOption(trustRootsOption) : null;
        return (roots != null && roots.Length > 0) || HasTrustPfx(parseResult);
    }

    internal bool HasTrustPfx(ParseResult parseResult)
    {
        var trustPfxOption = FindOption<FileInfo?>(parseResult, ClassStrings.OptionNameTrustPfx);
        var pfx = trustPfxOption != null ? parseResult.GetValueForOption(trustPfxOption) : null;
        return pfx?.Exists == true;
    }

    internal SecureString? GetTrustPfxPassword(ParseResult parseResult, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;

        if (!HasTrustPfx(parseResult))
        {
            return null;
        }

        var passwordFileOption = FindOption<FileInfo?>(parseResult, ClassStrings.OptionNameTrustPfxPasswordFile);
        var passwordFile = passwordFileOption != null ? parseResult.GetValueForOption(passwordFileOption) : null;
        if (passwordFile?.Exists == true)
        {
            logger.LogInformation(ClassStrings.InfoReadingPasswordFile, passwordFile.FullName);
            return SecurePasswordProvider.ReadPasswordFromFile(passwordFile.FullName);
        }

        var passwordEnvOption = FindOption<string?>(parseResult, ClassStrings.OptionNameTrustPfxPasswordEnv);
        var customEnvVar = passwordEnvOption != null ? parseResult.GetValueForOption(passwordEnvOption) : null;
        var envVarName = string.IsNullOrEmpty(customEnvVar) ? ClassStrings.DefaultTrustPfxPasswordEnvVar : customEnvVar;
        var envPassword = Environment.GetEnvironmentVariable(envVarName);
        if (!string.IsNullOrEmpty(envPassword))
        {
            logger.LogInformation(ClassStrings.InfoUsingEnvPassword, envVarName);
            return SecurePasswordProvider.ConvertToSecureString(envPassword);
        }

        return null;
    }

    internal bool IsTrustSystemRoots(ParseResult parseResult)
    {
        var trustSystemRootsOption = FindOption<bool>(parseResult, ClassStrings.OptionNameTrustSystemRoots);
        return trustSystemRootsOption != null && parseResult.GetValueForOption(trustSystemRootsOption);
    }

    internal bool IsAllowUntrusted(ParseResult parseResult)
    {
        var allowUntrustedOption = FindOption<bool>(parseResult, ClassStrings.OptionNameAllowUntrusted);
        return allowUntrustedOption != null && parseResult.GetValueForOption(allowUntrustedOption);
    }

    internal string? GetSubjectName(ParseResult parseResult)
    {
        var subjectNameOption = FindOption<string?>(parseResult, ClassStrings.OptionNameSubjectName);
        return subjectNameOption != null ? parseResult.GetValueForOption(subjectNameOption) : null;
    }

    internal string? GetIssuerName(ParseResult parseResult)
    {
        var issuerNameOption = FindOption<string?>(parseResult, ClassStrings.OptionNameIssuerName);
        return issuerNameOption != null ? parseResult.GetValueForOption(issuerNameOption) : null;
    }

    internal X509RevocationMode ParseRevocationMode(ParseResult parseResult)
    {
        var modeOption = FindOption<string>(parseResult, ClassStrings.OptionNameRevocationMode);
        var mode = modeOption != null ? parseResult.GetValueForOption(modeOption) : null;
        mode ??= ClassStrings.RevocationModeOnline;
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

        var trustRootsOption = FindOption<FileInfo[]?>(parseResult, ClassStrings.OptionNameTrustRoots);
        var roots = trustRootsOption != null ? parseResult.GetValueForOption(trustRootsOption) : null;
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

        var trustPfxOption = FindOption<FileInfo?>(parseResult, ClassStrings.OptionNameTrustPfx);
        var pfxFile = trustPfxOption != null ? parseResult.GetValueForOption(trustPfxOption) : null;
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
