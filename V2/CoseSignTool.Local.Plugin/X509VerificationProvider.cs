// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using CoseSignTool.Abstractions;

namespace CoseSignTool.Local.Plugin;

/// <summary>
/// Verification provider for X.509 certificate-based signature validation.
/// Supports system trust, custom trust roots, and certificate identity validation.
/// </summary>
public class X509VerificationProvider : IVerificationProvider
{
    internal static class ClassStrings
    {
        // Provider metadata
        public static readonly string ProviderNameValue = "X509";
        public static readonly string DescriptionValue = "X.509 certificate trust and identity validation";

        // Option names
        public static readonly string OptionNameTrustRoots = "--trust-roots";
        public static readonly string OptionAliasTrustRoots = "-r";
        public static readonly string OptionNameTrustSystemRoots = "--trust-system-roots";
        public static readonly string OptionNameAllowUntrusted = "--allow-untrusted";
        public static readonly string OptionNameSubjectName = "--subject-name";
        public static readonly string OptionAliasSubjectName = "-s";
        public static readonly string OptionNameIssuerName = "--issuer-name";
        public static readonly string OptionAliasIssuerName = "-i";
        public static readonly string OptionNameRevocationMode = "--revocation-mode";

        // Option descriptions
        public static readonly string DescriptionTrustRoots = "Path to trusted root certificate(s) in PEM or DER format. Repeat for multiple.";
        public static readonly string DescriptionTrustSystemRoots = "Trust system certificate store roots (default: true)";
        public static readonly string DescriptionAllowUntrusted = "Allow self-signed or untrusted root certificates";
        public static readonly string DescriptionSubjectName = "Required subject name (CN) in the signing certificate";
        public static readonly string DescriptionIssuerName = "Required issuer name (CN) in the signing certificate";
        public static readonly string DescriptionRevocationMode = "Certificate revocation check mode: online, offline, or none";

        // Revocation mode values
        public static readonly string RevocationModeOnline = "online";
        public static readonly string RevocationModeOffline = "offline";
        public static readonly string RevocationModeNone = "none";

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
    private Option<bool> TrustSystemRootsOption = null!;
    private Option<bool> AllowUntrustedOption = null!;
    private Option<string?> SubjectNameOption = null!;
    private Option<string?> IssuerNameOption = null!;
    private Option<string> RevocationModeOption = null!;

    /// <inheritdoc/>
    public void AddVerificationOptions(Command command)
    {
        // Trust options
        TrustRootsOption = new Option<FileInfo[]?>(
            name: ClassStrings.OptionNameTrustRoots,
            description: ClassStrings.DescriptionTrustRoots)
        {
            Arity = ArgumentArity.ZeroOrMore
        };
        TrustRootsOption.AddAlias(ClassStrings.OptionAliasTrustRoots);
        command.AddOption(TrustRootsOption);

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
            || HasSubjectNameRequirement(parseResult)
            || HasIssuerNameRequirement(parseResult)
            || !IsAllowUntrusted(parseResult); // Chain validation is on unless explicitly disabled
    }

    /// <inheritdoc/>
    public IEnumerable<IValidator<CoseSign1Message>> CreateValidators(ParseResult parseResult)
    {
        var validators = new List<IValidator<CoseSign1Message>>();

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
            validators.Add(new CertificateChainValidator(
                allowUnprotectedHeaders: true,
                allowUntrusted: IsAllowUntrusted(parseResult),
                revocationMode: revocationMode));
        }
        else if (IsAllowUntrusted(parseResult))
        {
            // Skip chain validation when explicitly allowing untrusted
            // but still add a minimal validator that accepts any chain
            validators.Add(new CertificateChainValidator(
                allowUnprotectedHeaders: true,
                allowUntrusted: true,
                revocationMode: X509RevocationMode.NoCheck));
        }

        // Add subject name validation
        if (HasSubjectNameRequirement(parseResult))
        {
            string subjectName = GetSubjectName(parseResult)!;
            validators.Add(new CertificateCommonNameValidator(subjectName, allowUnprotectedHeaders: true));
        }

        // Add issuer name validation
        if (HasIssuerNameRequirement(parseResult))
        {
            string issuerName = GetIssuerName(parseResult)!;
            validators.Add(new CertificateIssuerValidator(issuerName, allowUnprotectedHeaders: true));
        }

        return validators;
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
        return roots != null && roots.Length > 0;
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

        return collection;
    }

    #endregion
}