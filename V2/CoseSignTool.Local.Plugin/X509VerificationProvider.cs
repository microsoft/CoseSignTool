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
    /// <inheritdoc/>
    public string ProviderName => "X509";

    /// <inheritdoc/>
    public string Description => "X.509 certificate trust and identity validation";

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
            name: "--trust-roots",
            description: "Path to trusted root certificate(s) in PEM or DER format. Repeat for multiple.")
        {
            Arity = ArgumentArity.ZeroOrMore
        };
        TrustRootsOption.AddAlias("-r");
        command.AddOption(TrustRootsOption);

        TrustSystemRootsOption = new Option<bool>(
            name: "--trust-system-roots",
            getDefaultValue: () => true,
            description: "Trust system certificate store roots (default: true)");
        command.AddOption(TrustSystemRootsOption);

        AllowUntrustedOption = new Option<bool>(
            name: "--allow-untrusted",
            description: "Allow self-signed or untrusted root certificates");
        command.AddOption(AllowUntrustedOption);

        // Identity validation
        SubjectNameOption = new Option<string?>(
            name: "--subject-name",
            description: "Required subject name (CN) in the signing certificate");
        SubjectNameOption.AddAlias("-s");
        command.AddOption(SubjectNameOption);

        IssuerNameOption = new Option<string?>(
            name: "--issuer-name",
            description: "Required issuer name (CN) in the signing certificate");
        IssuerNameOption.AddAlias("-i");
        command.AddOption(IssuerNameOption);

        // Revocation checking
        RevocationModeOption = new Option<string>(
            name: "--revocation-mode",
            getDefaultValue: () => "online",
            description: "Certificate revocation check mode: online, offline, or none");
        RevocationModeOption.FromAmong("online", "offline", "none");
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
            ["Trust Mode"] = HasCustomTrustRoots(parseResult) ? "Custom Roots" :
                             IsAllowUntrusted(parseResult) ? "Untrusted Allowed" :
                             "System Trust"
        };

        if (HasSubjectNameRequirement(parseResult))
        {
            metadata["Required Subject"] = GetSubjectName(parseResult);
        }

        if (HasIssuerNameRequirement(parseResult))
        {
            metadata["Required Issuer"] = GetIssuerName(parseResult);
        }

        var revocationMode = ParseRevocationMode(parseResult);
        metadata["Revocation Check"] = revocationMode.ToString();

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
        var mode = parseResult.GetValueForOption(RevocationModeOption) ?? "online";
        return mode.ToLowerInvariant() switch
        {
            "online" => X509RevocationMode.Online,
            "offline" => X509RevocationMode.Offline,
            "none" => X509RevocationMode.NoCheck,
            _ => X509RevocationMode.Online
        };
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