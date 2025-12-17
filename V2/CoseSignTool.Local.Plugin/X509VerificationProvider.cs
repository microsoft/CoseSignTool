// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using CoseSignTool.Abstractions;
using CoseSignTool.Abstractions.Security;

namespace CoseSignTool.Local.Plugin;

/// <summary>
/// Verification provider for X.509 certificate-based signature validation.
/// Supports system trust, custom trust roots, and certificate identity validation.
/// </summary>
public class X509VerificationProvider : IVerificationProvider
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Provider metadata
        public static readonly string ProviderNameValue = "X509";
        public static readonly string DescriptionValue = "X.509 certificate trust and identity validation";

        // Option names
        public static readonly string OptionNameTrustRoots = "--trust-roots";
        public static readonly string OptionAliasTrustRoots = "-r";
        public static readonly string OptionNameTrustPfx = "--trust-pfx";
        public static readonly string OptionNameTrustPfxPasswordFile = "--trust-pfx-password-file";
        public static readonly string OptionNameTrustPfxPasswordEnv = "--trust-pfx-password-env";
        public static readonly string OptionNameTrustSystemRoots = "--trust-system-roots";
        public static readonly string OptionNameAllowUntrusted = "--allow-untrusted";
        public static readonly string OptionNameSubjectName = "--subject-name";
        public static readonly string OptionAliasSubjectName = "-s";
        public static readonly string OptionNameIssuerName = "--issuer-name";
        public static readonly string OptionAliasIssuerName = "-i";
        public static readonly string OptionNameRevocationMode = "--revocation-mode";

        // Option descriptions
        public static readonly string DescriptionTrustRoots = "Path to trusted root certificate(s) in PEM or DER format. Repeat for multiple.";
        public static readonly string DescriptionTrustPfx = "Path to PFX/PKCS#12 file containing trusted root certificate(s).";
        public static readonly string DescriptionTrustPfxPasswordFile = 
            "Path to a file containing the PFX password (more secure than command-line). " +
            "Alternatively, set COSESIGNTOOL_TRUST_PFX_PASSWORD environment variable.";
        public static readonly string DescriptionTrustPfxPasswordEnv = 
            "Name of environment variable containing the PFX password (default: COSESIGNTOOL_TRUST_PFX_PASSWORD)";
        public static readonly string DescriptionTrustSystemRoots = "Trust system certificate store roots (default: true)";
        public static readonly string DescriptionAllowUntrusted = "Allow self-signed or untrusted root certificates";
        public static readonly string DescriptionSubjectName = "Required subject name (CN) in the signing certificate";
        public static readonly string DescriptionIssuerName = "Required issuer name (CN) in the signing certificate";
        public static readonly string DescriptionRevocationMode = "Certificate revocation check mode: online, offline, or none";

        // Revocation mode values
        public static readonly string RevocationModeOnline = "online";
        public static readonly string RevocationModeOffline = "offline";
        public static readonly string RevocationModeNone = "none";

        // File extensions
        public static readonly string ExtensionPfx = ".pfx";
        public static readonly string ExtensionP12 = ".p12";

        // Environment variable default
        public static readonly string DefaultTrustPfxPasswordEnvVar = "COSESIGNTOOL_TRUST_PFX_PASSWORD";

        // Info messages
        public static readonly string InfoUsingEnvPassword = "Using trust PFX password from environment variable: {0}";
        public static readonly string InfoReadingPasswordFile = "Reading trust PFX password from file: {0}";

        // Metadata keys and values
        public static readonly string MetaKeyTrustMode = "Trust Mode";
        public static readonly string MetaKeyRequiredSubject = "Required Subject";
        public static readonly string MetaKeyRequiredIssuer = "Required Issuer";
        public static readonly string MetaKeyRevocationCheck = "Revocation Check";
        public static readonly string MetaValueCustomRoots = "Custom Roots";
        public static readonly string MetaValueUntrustedAllowed = "Untrusted Allowed";
        public static readonly string MetaValueSystemTrust = "System Trust";
    }

    /// <inheritdoc/>
    public string ProviderName => ClassStrings.ProviderNameValue;

    /// <inheritdoc/>
    public string Description => ClassStrings.DescriptionValue;

    /// <inheritdoc/>
    public int Priority => 10; // After signature validation (0)

    // Options stored as fields so we can read values from ParseResult
    private Option<FileInfo[]?> TrustRootsOption = null!;
    private Option<FileInfo?> TrustPfxOption = null!;
    private Option<FileInfo?> TrustPfxPasswordFileOption = null!;
    private Option<string?> TrustPfxPasswordEnvOption = null!;
    private Option<bool> TrustSystemRootsOption = null!;
    private Option<bool> AllowUntrustedOption = null!;
    private Option<string?> SubjectNameOption = null!;
    private Option<string?> IssuerNameOption = null!;
    private Option<string> RevocationModeOption = null!;

    /// <inheritdoc/>
    public void AddVerificationOptions(Command command)
    {
        // Trust options - PEM/DER certificates
        TrustRootsOption = new Option<FileInfo[]?>(
            name: ClassStrings.OptionNameTrustRoots,
            description: ClassStrings.DescriptionTrustRoots)
        {
            Arity = ArgumentArity.ZeroOrMore
        };
        TrustRootsOption.AddAlias(ClassStrings.OptionAliasTrustRoots);
        command.AddOption(TrustRootsOption);

        // Trust options - PFX with secure password handling
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

        // Identity validation
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

        // Revocation checking
        RevocationModeOption = new Option<string>(
            name: ClassStrings.OptionNameRevocationMode,
            getDefaultValue: () => ClassStrings.RevocationModeOnline,
            description: ClassStrings.DescriptionRevocationMode);
        RevocationModeOption.FromAmong(ClassStrings.RevocationModeOnline, ClassStrings.RevocationModeOffline, ClassStrings.RevocationModeNone);
        command.AddOption(RevocationModeOption);
    }

    /// <inheritdoc/>
    public bool IsActivated(ParseResult parseResult)
    {
        // X509 provider is activated if any X509-specific option is set
        // or if we should do chain validation (not allowing untrusted)
        return HasCustomTrustRoots(parseResult)
            || HasTrustPfx(parseResult)
            || HasSubjectNameRequirement(parseResult)
            || HasIssuerNameRequirement(parseResult)
            || !IsAllowUntrusted(parseResult); // Chain validation is on unless explicitly disabled
    }

    /// <inheritdoc/>
    public IEnumerable<IValidator<CoseSign1Message>> CreateValidators(ParseResult parseResult)
    {
        var validators = new List<IValidator<CoseSign1Message>>();

        bool HasX509Headers(CoseSign1Message message)
        {
            if (message == null)
            {
                return false;
            }

            bool hasX5t = message.ProtectedHeaders.ContainsKey(CertificateHeaderContributor.HeaderLabels.X5T)
                || message.UnprotectedHeaders.ContainsKey(CertificateHeaderContributor.HeaderLabels.X5T);
            bool hasX5chain = message.ProtectedHeaders.ContainsKey(CertificateHeaderContributor.HeaderLabels.X5Chain)
                || message.UnprotectedHeaders.ContainsKey(CertificateHeaderContributor.HeaderLabels.X5Chain);

            return hasX5t && hasX5chain;
        }

        IValidator<CoseSign1Message> WhenX509Headers(IValidator<CoseSign1Message> inner)
        {
            return new ConditionalX509Validator(inner, HasX509Headers);
        }

        // Parse revocation mode
        var revocationMode = ParseRevocationMode(parseResult);

        // Add chain validation if we have trust requirements
        if (HasCustomTrustRoots(parseResult))
        {
            var customRoots = LoadCustomRoots(parseResult);
            if (customRoots.Count > 0)
            {
                validators.Add(new CertificateChainValidator(
                    customRoots,
                    allowUnprotectedHeaders: true,
                    trustUserRoots: true,
                    revocationMode: revocationMode));
            }
        }
        else if (IsTrustSystemRoots(parseResult))
        {
            validators.Add(WhenX509Headers(new CertificateChainValidator(
                allowUnprotectedHeaders: true,
                allowUntrusted: IsAllowUntrusted(parseResult),
                revocationMode: revocationMode)));
        }
        else if (IsAllowUntrusted(parseResult))
        {
            // Skip chain validation when explicitly allowing untrusted
            // but still add a minimal validator that accepts any chain
            validators.Add(WhenX509Headers(new CertificateChainValidator(
                allowUnprotectedHeaders: true,
                allowUntrusted: true,
                revocationMode: X509RevocationMode.NoCheck)));
        }

        // Add subject name validation
        if (HasSubjectNameRequirement(parseResult))
        {
            string subjectName = GetSubjectName(parseResult)!;
            validators.Add(WhenX509Headers(new CertificateCommonNameValidator(subjectName, allowUnprotectedHeaders: true)));
        }

        // Add issuer name validation
        if (HasIssuerNameRequirement(parseResult))
        {
            string issuerName = GetIssuerName(parseResult)!;
            validators.Add(WhenX509Headers(new CertificateIssuerValidator(issuerName, allowUnprotectedHeaders: true)));
        }

        return validators;
    }

    private sealed class ConditionalX509Validator : IValidator<CoseSign1Message>, IConditionalValidator<CoseSign1Message>
    {
        private readonly IValidator<CoseSign1Message> Inner;
        private readonly Func<CoseSign1Message, bool> Predicate;

        public ConditionalX509Validator(IValidator<CoseSign1Message> inner, Func<CoseSign1Message, bool> predicate)
        {
            Inner = inner ?? throw new ArgumentNullException(nameof(inner));
            Predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
        }

        public bool IsApplicable(CoseSign1Message input) => Predicate(input);

        public ValidationResult Validate(CoseSign1Message input) => Inner.Validate(input);

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
            => Inner.ValidateAsync(input, cancellationToken);
    }

    /// <inheritdoc/>
    public IDictionary<string, object?> GetVerificationMetadata(
        ParseResult parseResult,
        CoseSign1Message message,
        ValidationResult validationResult)
    {
        var metadata = new Dictionary<string, object?>
        {
            [ClassStrings.MetaKeyTrustMode] = HasCustomTrustRoots(parseResult) ? ClassStrings.MetaValueCustomRoots :
                             IsAllowUntrusted(parseResult) ? ClassStrings.MetaValueUntrustedAllowed :
                             ClassStrings.MetaValueSystemTrust
        };

        if (HasSubjectNameRequirement(parseResult))
        {
            metadata[ClassStrings.MetaKeyRequiredSubject] = GetSubjectName(parseResult);
        }

        if (HasIssuerNameRequirement(parseResult))
        {
            metadata[ClassStrings.MetaKeyRequiredIssuer] = GetIssuerName(parseResult);
        }

        var revocationMode = ParseRevocationMode(parseResult);
        metadata[ClassStrings.MetaKeyRevocationCheck] = revocationMode.ToString();

        return metadata;
    }

    #region Helper Methods

    private bool HasCustomTrustRoots(ParseResult parseResult)
    {
        var roots = parseResult.GetValueForOption(TrustRootsOption);
        return (roots != null && roots.Length > 0) || HasTrustPfx(parseResult);
    }

    private bool HasTrustPfx(ParseResult parseResult)
    {
        var pfx = parseResult.GetValueForOption(TrustPfxOption);
        return pfx?.Exists == true;
    }

    private SecureString? GetTrustPfxPassword(ParseResult parseResult)
    {
        // Check password file first
        var passwordFile = parseResult.GetValueForOption(TrustPfxPasswordFileOption);
        if (passwordFile?.Exists == true)
        {
            Console.WriteLine(string.Format(ClassStrings.InfoReadingPasswordFile, passwordFile.FullName));
            return SecurePasswordProvider.ReadPasswordFromFile(passwordFile.FullName);
        }

        // Check custom env var option, fallback to default env var
        var customEnvVar = parseResult.GetValueForOption(TrustPfxPasswordEnvOption);
        var envVarName = string.IsNullOrEmpty(customEnvVar) ? ClassStrings.DefaultTrustPfxPasswordEnvVar : customEnvVar;
        var envPassword = Environment.GetEnvironmentVariable(envVarName);
        if (!string.IsNullOrEmpty(envPassword))
        {
            Console.WriteLine(string.Format(ClassStrings.InfoUsingEnvPassword, envVarName));
            return SecurePasswordProvider.ConvertToSecureString(envPassword);
        }

        // Return null - PFX may be unprotected
        return null;
    }

    private bool IsTrustSystemRoots(ParseResult parseResult)
    {
        return parseResult.GetValueForOption(TrustSystemRootsOption);
    }

    private bool IsAllowUntrusted(ParseResult parseResult)
    {
        return parseResult.GetValueForOption(AllowUntrustedOption);
    }

    private bool HasSubjectNameRequirement(ParseResult parseResult)
    {
        var name = parseResult.GetValueForOption(SubjectNameOption);
        return !string.IsNullOrEmpty(name);
    }

    private bool HasIssuerNameRequirement(ParseResult parseResult)
    {
        var name = parseResult.GetValueForOption(IssuerNameOption);
        return !string.IsNullOrEmpty(name);
    }

    private string? GetSubjectName(ParseResult parseResult)
    {
        return parseResult.GetValueForOption(SubjectNameOption);
    }

    private string? GetIssuerName(ParseResult parseResult)
    {
        return parseResult.GetValueForOption(IssuerNameOption);
    }

    private X509RevocationMode ParseRevocationMode(ParseResult parseResult)
    {
        var mode = parseResult.GetValueForOption(RevocationModeOption) ?? ClassStrings.RevocationModeOnline;
        var modeLower = mode.ToLowerInvariant();
        if (modeLower == ClassStrings.RevocationModeOnline)
        {
            return X509RevocationMode.Online;
        }
        else if (modeLower == ClassStrings.RevocationModeOffline)
        {
            return X509RevocationMode.Offline;
        }
        else if (modeLower == ClassStrings.RevocationModeNone)
        {
            return X509RevocationMode.NoCheck;
        }
        else
        {
            return X509RevocationMode.Online;
        }
    }

    private X509Certificate2Collection LoadCustomRoots(ParseResult parseResult)
    {
        var collection = new X509Certificate2Collection();

        // Load individual certificate files
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
                        // Skip invalid certificates
                    }
                }
            }
        }

        // Load certificates from PFX file
        var pfxFile = parseResult.GetValueForOption(TrustPfxOption);
        if (pfxFile?.Exists == true)
        {
            try
            {
                var password = GetTrustPfxPassword(parseResult);
                X509Certificate2Collection pfxCollection;

                // Load from PFX using the new X509CertificateLoader API
                if (password != null)
                {
                    pfxCollection = X509CertificateLoader.LoadPkcs12CollectionFromFile(
                        pfxFile.FullName,
                        SecurePasswordProvider.ConvertToPlainString(password),
                        X509KeyStorageFlags.DefaultKeySet);
                }
                else
                {
                    pfxCollection = X509CertificateLoader.LoadPkcs12CollectionFromFile(
                        pfxFile.FullName,
                        password: null,
                        X509KeyStorageFlags.DefaultKeySet);
                }

                collection.AddRange(pfxCollection);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to load PFX trust store: {ex.Message}");
            }
        }

        return collection;
    }

    #endregion
}