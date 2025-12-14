// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Local;
using CoseSignTool.Abstractions;
using Microsoft.Extensions.Logging;

namespace CoseSignTool.Local.Plugin;

/// <summary>
/// Command provider for signing with ephemeral (in-memory) certificates.
/// Creates certificates on-the-fly for testing, development, and prototyping.
/// </summary>
/// <remarks>
/// <para>
/// Ephemeral certificates are generated in memory and never persisted to disk.
/// They are suitable for:
/// </para>
/// <list type="bullet">
/// <item>Testing COSE signing/verification workflows</item>
/// <item>Development and prototyping</item>
/// <item>CI/CD pipeline testing</item>
/// <item>Scenarios where real certificates are not available</item>
/// </list>
/// <para>
/// <b>Default Configuration:</b> RSA-4096 with a full certificate chain (Root → Intermediate → Leaf)
/// and CodeSigning EKU for maximum compatibility with COSE signing scenarios.
/// </para>
/// <para>
/// <b>Custom Configuration:</b> Provide a JSON configuration file via --config to customize
/// all aspects of the certificate including algorithm, key size, validity, EKUs, and chain structure.
/// </para>
/// <para>
/// <b>WARNING:</b> Ephemeral certificates should NOT be used in production.
/// Signatures created with ephemeral certificates cannot be verified by external parties
/// because the certificate chain is not published or trusted.
/// </para>
/// </remarks>
public class EphemeralSigningCommandProvider : ISigningCommandProvider
{
    private readonly EphemeralCertificateFactory CertificateFactory = new();
    private readonly CertificateChainFactory ChainFactory;
    private ISigningService<CoseSign1.Abstractions.SigningOptions>? SigningService;
    private string? CertificateSubject;
    private string? CertificateThumbprint;
    private string? KeyAlgorithmField;
    private bool UsedChain;
    private string? ConfigSource;

    /// <summary>
    /// Initializes a new instance of the <see cref="EphemeralSigningCommandProvider"/> class.
    /// </summary>
    public EphemeralSigningCommandProvider()
    {
        ChainFactory = new CertificateChainFactory(CertificateFactory);
    }

    /// <inheritdoc/>
    public string CommandName => "sign-ephemeral";

    /// <inheritdoc/>
    public string CommandDescription =>
        "Sign with an ephemeral (in-memory) certificate for testing. " +
        "Default: RSA-4096 with full certificate chain and CodeSigning EKU.";

    /// <inheritdoc/>
    public string ExampleUsage => "[--config cert-config.json] | [--subject \"CN=Test\"]";

    /// <inheritdoc/>
    public void AddCommandOptions(Command command)
    {
        var configOption = new Option<FileInfo?>(
            name: "--config",
            description: "Path to JSON configuration file for certificate settings. " +
                        "If not provided, uses optimal defaults (RSA-4096, full chain, CodeSigning EKU).")
        {
            IsRequired = false
        };

        var subjectOption = new Option<string?>(
            name: "--subject",
            description: "Certificate subject name. Overrides config file if both specified.")
        {
            IsRequired = false
        };

        var algorithmOption = new Option<string?>(
            name: "--algorithm",
            description: "Key algorithm: RSA (default), ECDSA, or MLDSA (post-quantum). Overrides config file.")
        {
            IsRequired = false
        };
        algorithmOption.FromAmong("RSA", "ECDSA", "MLDSA");

        var keySizeOption = new Option<int?>(
            name: "--key-size",
            description: "Key size in bits. Overrides config file. " +
                        "Defaults: RSA=4096, ECDSA=384, MLDSA=65")
        {
            IsRequired = false
        };

        var validityDaysOption = new Option<int?>(
            name: "--validity-days",
            description: "Certificate validity period in days. Overrides config file. Default: 365")
        {
            IsRequired = false
        };

        var noChainOption = new Option<bool>(
            name: "--no-chain",
            description: "Generate a self-signed certificate instead of a full chain. " +
                        "By default, generates Root → Intermediate → Leaf chain.")
        {
            IsRequired = false
        };
        noChainOption.SetDefaultValue(false);

        var minimalOption = new Option<bool>(
            name: "--minimal",
            description: "Use minimal configuration (RSA-2048, self-signed, 1 day validity) for quick tests.")
        {
            IsRequired = false
        };
        minimalOption.SetDefaultValue(false);

        var pqcOption = new Option<bool>(
            name: "--pqc",
            description: "Use post-quantum cryptography (ML-DSA-65 with full chain).")
        {
            IsRequired = false
        };
        pqcOption.SetDefaultValue(false);

        command.AddOption(configOption);
        command.AddOption(subjectOption);
        command.AddOption(algorithmOption);
        command.AddOption(keySizeOption);
        command.AddOption(validityDaysOption);
        command.AddOption(noChainOption);
        command.AddOption(minimalOption);
        command.AddOption(pqcOption);
    }

    /// <inheritdoc/>
    public async Task<ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(
        IDictionary<string, object?> options)
    {
        // Get logger factory if provided
        var loggerFactory = options.TryGetValue("__loggerFactory", out var lf) ? lf as ILoggerFactory : null;
        var logger = loggerFactory?.CreateLogger<EphemeralSigningCommandProvider>();

        // Load configuration
        var config = LoadConfiguration(options, logger);

        // Apply command-line overrides
        ApplyCommandLineOverrides(config, options);

        logger?.LogInformation(
            "Creating ephemeral certificate. Subject: {Subject}, Algorithm: {Algorithm}, KeySize: {KeySize}, " +
            "ValidityDays: {ValidityDays}, GenerateChain: {GenerateChain}, EKUs: {EKUs}",
            config.Subject,
            config.Algorithm,
            config.EffectiveKeySize,
            config.ValidityDays,
            config.GenerateChain,
            string.Join(", ", config.EffectiveEnhancedKeyUsages));

        // Map algorithm string to enum
        var algorithm = config.Algorithm?.ToUpperInvariant() switch
        {
            "RSA" => KeyAlgorithm.RSA,
            "ECDSA" => KeyAlgorithm.ECDSA,
            "MLDSA" => KeyAlgorithm.MLDSA,
            _ => KeyAlgorithm.RSA
        };

        X509Certificate2 signingCert;
        IReadOnlyList<X509Certificate2> chain;

        if (config.GenerateChain)
        {
            // Create full certificate chain
            var chainConfig = config.EffectiveChainConfig;
            var chainCollection = ChainFactory.CreateChain(o =>
            {
                o.WithLeafName(config.Subject)
                 .WithRootName(chainConfig.RootSubject)
                 .WithIntermediateName(chainConfig.IntermediateSubject)
                 .WithKeyAlgorithm(algorithm)
                 .WithKeySize(config.EffectiveKeySize);

                o.RootValidity = TimeSpan.FromDays(chainConfig.RootValidityDays);
                o.IntermediateValidity = TimeSpan.FromDays(chainConfig.IntermediateValidityDays);
                o.LeafValidity = TimeSpan.FromDays(config.ValidityDays);
            });

            // Extract signing cert (leaf) and chain
            signingCert = chainCollection[^1]; // Last is leaf
            chain = chainCollection.Cast<X509Certificate2>().ToList();
            UsedChain = true;
        }
        else
        {
            // Create single self-signed certificate
            signingCert = CertificateFactory.CreateCertificate(o =>
            {
                o.WithSubjectName(config.Subject)
                 .WithKeyAlgorithm(algorithm)
                 .WithKeySize(config.EffectiveKeySize)
                 .WithNotBeforeOffset(TimeSpan.FromMinutes(-5))
                 .WithValidity(TimeSpan.FromDays(config.ValidityDays));

                // Apply EKUs
                foreach (var eku in config.EffectiveEnhancedKeyUsages)
                {
                    ApplyEku(o, eku);
                }
            });

            chain = new[] { signingCert };
            UsedChain = false;
        }

        // Store metadata for later display
        CertificateSubject = signingCert.Subject;
        CertificateThumbprint = signingCert.Thumbprint;
        KeyAlgorithmField = $"{config.Algorithm} ({config.EffectiveKeySize} bits)";

        // Create logger for signing service
        var signingServiceLogger = loggerFactory?.CreateLogger<LocalCertificateSigningService>();

        // Create and return signing service
        SigningService = new LocalCertificateSigningService(signingCert, chain, signingServiceLogger);

        return await Task.FromResult(SigningService);
    }

    private EphemeralCertificateConfig LoadConfiguration(IDictionary<string, object?> options, ILogger? logger)
    {
        // Check for preset configurations first
        if (options.TryGetValue("minimal", out var minVal) && minVal is true)
        {
            ConfigSource = "Minimal preset";
            logger?.LogDebug("Using minimal configuration preset");
            return EphemeralCertificateConfig.CreateMinimal();
        }

        if (options.TryGetValue("pqc", out var pqcVal) && pqcVal is true)
        {
            ConfigSource = "Post-Quantum preset";
            logger?.LogDebug("Using post-quantum configuration preset");
            return EphemeralCertificateConfig.CreatePostQuantum();
        }

        // Check for config file
        if (options.TryGetValue("config", out var configVal) && configVal is FileInfo configFile)
        {
            if (!configFile.Exists)
            {
                throw new FileNotFoundException($"Configuration file not found: {configFile.FullName}");
            }

            ConfigSource = $"Config file: {configFile.Name}";
            logger?.LogDebug("Loading configuration from file: {ConfigFile}", configFile.FullName);
            return EphemeralCertificateConfig.LoadFromFile(configFile.FullName);
        }

        // Use optimal defaults
        ConfigSource = "Default (RSA-4096, full chain, CodeSigning)";
        logger?.LogDebug("Using default configuration");
        return EphemeralCertificateConfig.CreateDefault();
    }

    private static void ApplyCommandLineOverrides(EphemeralCertificateConfig config, IDictionary<string, object?> options)
    {
        if (options.TryGetValue("subject", out var subj) && subj is string subject && !string.IsNullOrEmpty(subject))
        {
            config.Subject = subject;
        }

        if (options.TryGetValue("algorithm", out var algo) && algo is string algorithm && !string.IsNullOrEmpty(algorithm))
        {
            config.Algorithm = algorithm.ToUpperInvariant();
            // Reset key size to use new algorithm default
            config.KeySize = null;
        }

        if (options.TryGetValue("key-size", out var ks) && ks is int keySize)
        {
            config.KeySize = keySize;
        }

        if (options.TryGetValue("validity-days", out var vd) && vd is int validityDays)
        {
            config.ValidityDays = validityDays;
        }

        if (options.TryGetValue("no-chain", out var nc) && nc is true)
        {
            config.GenerateChain = false;
        }
    }

    private static void ApplyEku(CertificateOptions o, string eku)
    {
        switch (eku.ToUpperInvariant())
        {
            case "CODESIGNING":
            case "CODE_SIGNING":
                o.ForCodeSigning();
                break;
            case "LIFETIMESIGNING":
            case "LIFETIME_SIGNING":
                o.WithLifetimeSigning();
                break;
            case "SERVERAUTH":
            case "SERVER_AUTH":
            case "TLSSERVER":
                o.WithEnhancedKeyUsages(EnhancedKeyUsageOids.ServerAuthentication);
                break;
            case "CLIENTAUTH":
            case "CLIENT_AUTH":
            case "TLSCLIENT":
                o.WithEnhancedKeyUsages(EnhancedKeyUsageOids.ClientAuthentication);
                break;
            case "TIMESTAMPING":
            case "TIME_STAMPING":
                o.WithEnhancedKeyUsages(EnhancedKeyUsageOids.TimeStamping);
                break;
            default:
                // Assume it's a raw OID
                o.WithEnhancedKeyUsages(eku);
                break;
        }
    }

    /// <inheritdoc/>
    public IDictionary<string, string> GetSigningMetadata()
    {
        var metadata = new Dictionary<string, string>
        {
            ["Certificate Source"] = "Ephemeral (in-memory)",
            ["Configuration"] = ConfigSource ?? "Unknown",
            ["Certificate Subject"] = CertificateSubject ?? "Unknown",
            ["Certificate Thumbprint"] = CertificateThumbprint ?? "Unknown",
            ["Key Algorithm"] = KeyAlgorithmField ?? "Unknown",
            ["Certificate Chain"] = UsedChain ? "Root → Intermediate → Leaf" : "Self-signed",
            ["⚠️ Warning"] = "Ephemeral certificates are for testing only"
        };

        return metadata;
    }
}