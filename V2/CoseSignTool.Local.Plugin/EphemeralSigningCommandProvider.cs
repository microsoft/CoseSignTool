// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates;
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
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Command metadata
        public static readonly string CommandNameValue = "sign-ephemeral";
        public static readonly string CommandDescriptionValue =
            "Sign with an ephemeral (in-memory) certificate for testing. " +
            "Default: RSA-4096 with full certificate chain and CodeSigning EKU.";
        public static readonly string ExampleUsageValue = "[--config cert-config.json] | [--subject \"CN=Test\"]";

        // Option names
        public static readonly string OptionNameConfig = "--config";
        public static readonly string OptionNameSubject = "--subject";
        public static readonly string OptionNameAlgorithm = "--algorithm";
        public static readonly string OptionNameKeySize = "--key-size";
        public static readonly string OptionNameValidityDays = "--validity-days";
        public static readonly string OptionNameNoChain = "--no-chain";
        public static readonly string OptionNameMinimal = "--minimal";
        public static readonly string OptionNamePqc = "--pqc";

        // Option descriptions
        public static readonly string DescriptionConfig =
            "Path to JSON configuration file for certificate settings. " +
            "If not provided, uses optimal defaults (RSA-4096, full chain, CodeSigning EKU).";
        public static readonly string DescriptionSubject = "Certificate subject name. Overrides config file if both specified.";
        public static readonly string DescriptionAlgorithm = "Key algorithm: RSA (default), ECDSA, or MLDSA (post-quantum). Overrides config file.";
        public static readonly string DescriptionKeySize =
            "Key size in bits. Overrides config file. " +
            "Defaults: RSA=4096, ECDSA=384, MLDSA=65";
        public static readonly string DescriptionValidityDays = "Certificate validity period in days. Overrides config file. Default: 365";
        public static readonly string DescriptionNoChain =
            "Generate a self-signed certificate instead of a full chain. " +
            "By default, generates Root → Intermediate → Leaf chain.";
        public static readonly string DescriptionMinimal = "Use minimal configuration (RSA-2048, self-signed, 1 day validity) for quick tests.";
        public static readonly string DescriptionPqc = "Use post-quantum cryptography (ML-DSA-65 with full chain).";

        // Dictionary keys (internal)
        public static readonly string KeyLoggerFactory = "__loggerFactory";
        public static readonly string KeyMinimal = "minimal";
        public static readonly string KeyPqc = "pqc";
        public static readonly string KeyConfig = "config";
        public static readonly string KeySubject = "subject";
        public static readonly string KeyAlgorithm = "algorithm";
        public static readonly string KeyKeySize = "key-size";
        public static readonly string KeyValidityDays = "validity-days";
        public static readonly string KeyNoChain = "no-chain";

        // Algorithm names
        public static readonly string AlgorithmRsa = "RSA";
        public static readonly string AlgorithmEcdsa = "ECDSA";
        public static readonly string AlgorithmMldsa = "MLDSA";

        // EKU names (for switch matching)
        public static readonly string EkuCodeSigning = "CODESIGNING";
        public static readonly string EkuCodeSigningAlt = "CODE_SIGNING";
        public static readonly string EkuLifetimeSigning = "LIFETIMESIGNING";
        public static readonly string EkuLifetimeSigningAlt = "LIFETIME_SIGNING";
        public static readonly string EkuServerAuth = "SERVERAUTH";
        public static readonly string EkuServerAuthAlt = "SERVER_AUTH";
        public static readonly string EkuTlsServer = "TLSSERVER";
        public static readonly string EkuClientAuth = "CLIENTAUTH";
        public static readonly string EkuClientAuthAlt = "CLIENT_AUTH";
        public static readonly string EkuTlsClient = "TLSCLIENT";
        public static readonly string EkuTimestamping = "TIMESTAMPING";
        public static readonly string EkuTimestampingAlt = "TIME_STAMPING";

        // Config source descriptions
        public static readonly string ConfigSourceMinimal = "Minimal preset";
        public static readonly string ConfigSourcePqc = "Post-Quantum preset";
        public static readonly string ConfigSourceDefault = "Default (RSA-4096, full chain, CodeSigning)";

        // Metadata keys and values
        public static readonly string MetaKeyCertSource = "Certificate Source";
        public static readonly string MetaKeyConfiguration = "Configuration";
        public static readonly string MetaKeyCertSubject = "Certificate Subject";
        public static readonly string MetaKeyCertThumbprint = "Certificate Thumbprint";
        public static readonly string MetaKeyKeyAlgorithm = "Key Algorithm";
        public static readonly string MetaKeyCertChain = "Certificate Chain";
        public static readonly string MetaKeyWarning = "⚠️ Warning";
        public static readonly string MetaValueEphemeral = "Ephemeral (in-memory)";
        public static readonly string MetaValueUnknown = "Unknown";
        public static readonly string MetaValueChainFull = "Root → Intermediate → Leaf";
        public static readonly string MetaValueSelfSigned = "Self-signed";
        public static readonly string MetaValueWarning = "Ephemeral certificates are for testing only";

        // Key algorithm format
        public static readonly string FormatKeyAlgorithm = "{0} ({1} bits)";

        // Log message templates
        public static readonly string LogCreatingCert =
            "Creating ephemeral certificate. Subject: {Subject}, Algorithm: {Algorithm}, KeySize: {KeySize}, " +
            "ValidityDays: {ValidityDays}, GenerateChain: {GenerateChain}, EKUs: {EKUs}";
        public static readonly string LogUsingMinimal = "Using minimal configuration preset";
        public static readonly string LogUsingPqc = "Using post-quantum configuration preset";
        public static readonly string LogLoadingFromFile = "Loading configuration from file: {ConfigFile}";
        public static readonly string LogUsingDefault = "Using default configuration";

        // Error messages
        public static readonly string ErrorConfigNotFound = "Configuration file not found: {0}";
    }

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
    public string CommandName => ClassStrings.CommandNameValue;

    /// <inheritdoc/>
    public string CommandDescription => ClassStrings.CommandDescriptionValue;

    /// <inheritdoc/>
    public string ExampleUsage => ClassStrings.ExampleUsageValue;

    /// <inheritdoc/>
    public void AddCommandOptions(Command command)
    {
        var configOption = new Option<FileInfo?>(
            name: ClassStrings.OptionNameConfig,
            description: ClassStrings.DescriptionConfig)
        {
            IsRequired = false
        };

        var subjectOption = new Option<string?>(
            name: ClassStrings.OptionNameSubject,
            description: ClassStrings.DescriptionSubject)
        {
            IsRequired = false
        };

        var algorithmOption = new Option<string?>(
            name: ClassStrings.OptionNameAlgorithm,
            description: ClassStrings.DescriptionAlgorithm)
        {
            IsRequired = false
        };
        algorithmOption.FromAmong(ClassStrings.AlgorithmRsa, ClassStrings.AlgorithmEcdsa, ClassStrings.AlgorithmMldsa);

        var keySizeOption = new Option<int?>(
            name: ClassStrings.OptionNameKeySize,
            description: ClassStrings.DescriptionKeySize)
        {
            IsRequired = false
        };

        var validityDaysOption = new Option<int?>(
            name: ClassStrings.OptionNameValidityDays,
            description: ClassStrings.DescriptionValidityDays)
        {
            IsRequired = false
        };

        var noChainOption = new Option<bool>(
            name: ClassStrings.OptionNameNoChain,
            description: ClassStrings.DescriptionNoChain)
        {
            IsRequired = false
        };
        noChainOption.SetDefaultValue(false);

        var minimalOption = new Option<bool>(
            name: ClassStrings.OptionNameMinimal,
            description: ClassStrings.DescriptionMinimal)
        {
            IsRequired = false
        };
        minimalOption.SetDefaultValue(false);

        var pqcOption = new Option<bool>(
            name: ClassStrings.OptionNamePqc,
            description: ClassStrings.DescriptionPqc)
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
        var loggerFactory = options.TryGetValue(ClassStrings.KeyLoggerFactory, out var lf) ? lf as ILoggerFactory : null;
        var logger = loggerFactory?.CreateLogger<EphemeralSigningCommandProvider>();

        // Load configuration
        var config = LoadConfiguration(options, logger);

        // Apply command-line overrides
        ApplyCommandLineOverrides(config, options);

        logger?.LogInformation(
            ClassStrings.LogCreatingCert,
            config.Subject,
            config.Algorithm,
            config.EffectiveKeySize,
            config.ValidityDays,
            config.GenerateChain,
            string.Join(", ", config.EffectiveEnhancedKeyUsages));

        // Map algorithm string to enum
        var algorithmUpper = config.Algorithm?.ToUpperInvariant();
        KeyAlgorithm algorithm;
        if (algorithmUpper == ClassStrings.AlgorithmEcdsa)
        {
            algorithm = KeyAlgorithm.ECDSA;
        }
        else if (algorithmUpper == ClassStrings.AlgorithmMldsa)
        {
            algorithm = KeyAlgorithm.MLDSA;
        }
        else
        {
            algorithm = KeyAlgorithm.RSA;
        }

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
        KeyAlgorithmField = string.Format(ClassStrings.FormatKeyAlgorithm, config.Algorithm, config.EffectiveKeySize);

        // Create logger for signing service
        var signingServiceLogger = loggerFactory?.CreateLogger<CertificateSigningService>();

        // Create and return signing service
        SigningService = CertificateSigningService.Create(signingCert, (IReadOnlyList<X509Certificate2>)chain, signingServiceLogger);

        return await Task.FromResult(SigningService);
    }

    private EphemeralCertificateConfig LoadConfiguration(IDictionary<string, object?> options, ILogger? logger)
    {
        // Check for preset configurations first
        if (options.TryGetValue(ClassStrings.KeyMinimal, out var minVal) && minVal is true)
        {
            ConfigSource = ClassStrings.ConfigSourceMinimal;
            logger?.LogDebug(ClassStrings.LogUsingMinimal);
            return EphemeralCertificateConfig.CreateMinimal();
        }

        if (options.TryGetValue(ClassStrings.KeyPqc, out var pqcVal) && pqcVal is true)
        {
            ConfigSource = ClassStrings.ConfigSourcePqc;
            logger?.LogDebug(ClassStrings.LogUsingPqc);
            return EphemeralCertificateConfig.CreatePostQuantum();
        }

        // Check for config file
        if (options.TryGetValue(ClassStrings.KeyConfig, out var configVal) && configVal is FileInfo configFile)
        {
            if (!configFile.Exists)
            {
                throw new FileNotFoundException(string.Format(ClassStrings.ErrorConfigNotFound, configFile.FullName));
            }

            ConfigSource = $"Config file: {configFile.Name}";
            logger?.LogDebug(ClassStrings.LogLoadingFromFile, configFile.FullName);
            return EphemeralCertificateConfig.LoadFromFile(configFile.FullName);
        }

        // Use optimal defaults
        ConfigSource = ClassStrings.ConfigSourceDefault;
        logger?.LogDebug(ClassStrings.LogUsingDefault);
        return EphemeralCertificateConfig.CreateDefault();
    }

    private static void ApplyCommandLineOverrides(EphemeralCertificateConfig config, IDictionary<string, object?> options)
    {
        if (options.TryGetValue(ClassStrings.KeySubject, out var subj) && subj is string subject && !string.IsNullOrEmpty(subject))
        {
            config.Subject = subject;
        }

        if (options.TryGetValue(ClassStrings.KeyAlgorithm, out var algo) && algo is string algorithm && !string.IsNullOrEmpty(algorithm))
        {
            config.Algorithm = algorithm.ToUpperInvariant();
            // Reset key size to use new algorithm default
            config.KeySize = null;
        }

        if (options.TryGetValue(ClassStrings.KeyKeySize, out var ks) && ks is int keySize)
        {
            config.KeySize = keySize;
        }

        if (options.TryGetValue(ClassStrings.KeyValidityDays, out var vd) && vd is int validityDays)
        {
            config.ValidityDays = validityDays;
        }

        if (options.TryGetValue(ClassStrings.KeyNoChain, out var nc) && nc is true)
        {
            config.GenerateChain = false;
        }
    }

    private static void ApplyEku(CertificateOptions o, string eku)
    {
        var ekuUpper = eku.ToUpperInvariant();
        if (ekuUpper == ClassStrings.EkuCodeSigning || ekuUpper == ClassStrings.EkuCodeSigningAlt)
        {
            o.ForCodeSigning();
        }
        else if (ekuUpper == ClassStrings.EkuLifetimeSigning || ekuUpper == ClassStrings.EkuLifetimeSigningAlt)
        {
            o.WithLifetimeSigning();
        }
        else if (ekuUpper == ClassStrings.EkuServerAuth || ekuUpper == ClassStrings.EkuServerAuthAlt || ekuUpper == ClassStrings.EkuTlsServer)
        {
            o.WithEnhancedKeyUsages(EnhancedKeyUsageOids.ServerAuthentication);
        }
        else if (ekuUpper == ClassStrings.EkuClientAuth || ekuUpper == ClassStrings.EkuClientAuthAlt || ekuUpper == ClassStrings.EkuTlsClient)
        {
            o.WithEnhancedKeyUsages(EnhancedKeyUsageOids.ClientAuthentication);
        }
        else if (ekuUpper == ClassStrings.EkuTimestamping || ekuUpper == ClassStrings.EkuTimestampingAlt)
        {
            o.WithEnhancedKeyUsages(EnhancedKeyUsageOids.TimeStamping);
        }
        else
        {
            // Assume it's a raw OID
            o.WithEnhancedKeyUsages(eku);
        }
    }

    /// <inheritdoc/>
    public IDictionary<string, string> GetSigningMetadata()
    {
        var metadata = new Dictionary<string, string>
        {
            [ClassStrings.MetaKeyCertSource] = ClassStrings.MetaValueEphemeral,
            [ClassStrings.MetaKeyConfiguration] = ConfigSource ?? ClassStrings.MetaValueUnknown,
            [ClassStrings.MetaKeyCertSubject] = CertificateSubject ?? ClassStrings.MetaValueUnknown,
            [ClassStrings.MetaKeyCertThumbprint] = CertificateThumbprint ?? ClassStrings.MetaValueUnknown,
            [ClassStrings.MetaKeyKeyAlgorithm] = KeyAlgorithmField ?? ClassStrings.MetaValueUnknown,
            [ClassStrings.MetaKeyCertChain] = UsedChain ? ClassStrings.MetaValueChainFull : ClassStrings.MetaValueSelfSigned,
            [ClassStrings.MetaKeyWarning] = ClassStrings.MetaValueWarning
        };

        return metadata;
    }
}