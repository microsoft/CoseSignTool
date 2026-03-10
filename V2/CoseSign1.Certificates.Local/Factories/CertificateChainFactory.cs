// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Factory for creating certificate chains (root → intermediate → leaf).
/// </summary>
/// <remarks>
/// <para>
/// Creates hierarchical certificate chains suitable for testing certificate
/// validation, chain building, and production-like signing scenarios.
/// </para>
/// </remarks>
public partial class CertificateChainFactory
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Keep only non-log messages
    }

    #region LoggerMessage methods

    [LoggerMessage(
        EventId = 4001,
        Level = LogLevel.Debug,
        Message = "Creating certificate chain. Algorithm: {Algorithm}, HasIntermediate: {HasIntermediate}")]
    private partial void LogCreatingCertificateChain(KeyAlgorithm algorithm, bool hasIntermediate);

    [LoggerMessage(
        EventId = 4002,
        Level = LogLevel.Trace,
        Message = "Created root CA: {SerialNumber}")]
    private partial void LogCreatedRootCa(string serialNumber);

    [LoggerMessage(
        EventId = 4003,
        Level = LogLevel.Trace,
        Message = "Created intermediate CA: {SerialNumber}")]
    private partial void LogCreatedIntermediateCa(string serialNumber);

    [LoggerMessage(
        EventId = 4004,
        Level = LogLevel.Trace,
        Message = "Created leaf certificate: {Subject}")]
    private partial void LogCreatedLeafCertificate(string subject);

    [LoggerMessage(
        EventId = 4005,
        Level = LogLevel.Debug,
        Message = "Certificate chain created successfully. CertificateCount: {Count}, ElapsedMs: {ElapsedMs}")]
    private partial void LogCertificateChainCreatedSuccessfully(int count, long elapsedMs);

    #endregion

    private readonly EphemeralCertificateFactory CertificateFactory;
    private readonly ILogger<CertificateChainFactory> Logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateChainFactory"/> class.
    /// </summary>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public CertificateChainFactory(ILogger<CertificateChainFactory>? logger = null)
        : this(new EphemeralCertificateFactory(), logger)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateChainFactory"/> class
    /// with a custom certificate factory.
    /// </summary>
    /// <param name="certificateFactory">The certificate factory to use.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateFactory"/> is <see langword="null"/>.</exception>
    public CertificateChainFactory(
        EphemeralCertificateFactory certificateFactory,
        ILogger<CertificateChainFactory>? logger = null)
    {
        CertificateFactory = certificateFactory ?? throw new ArgumentNullException(nameof(certificateFactory));
        Logger = logger ?? NullLogger<CertificateChainFactory>.Instance;
    }

    /// <summary>
    /// Creates a certificate chain with default options.
    /// </summary>
    /// <returns>Collection of certificates (root, intermediate, leaf).</returns>
    public X509Certificate2Collection CreateChain()
    {
        return CreateChain(_ => { });
    }

    /// <summary>
    /// Creates a certificate chain with configured options.
    /// </summary>
    /// <param name="configure">Action to configure chain options.</param>
    /// <returns>Collection of certificates in configured order.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="configure"/> is <see langword="null"/>.</exception>
    public X509Certificate2Collection CreateChain(Action<CertificateChainOptions> configure)
    {
        if (configure == null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        var options = new CertificateChainOptions();
        configure(options);

        return CreateChainInternal(options);
    }

    private X509Certificate2Collection CreateChainInternal(CertificateChainOptions options)
    {
        var stopwatch = Stopwatch.StartNew();

        LogCreatingCertificateChain(options.KeyAlgorithm, options.IntermediateName != null);

        var result = new X509Certificate2Collection();

        // Create root CA
        var root = CertificateFactory.CreateCertificate(o => o
            .WithSubjectName(options.RootName)
            .WithKeyAlgorithm(options.KeyAlgorithm)
            .WithKeySize(options.KeySize ?? GetDefaultKeySize(options.KeyAlgorithm))
            .WithValidity(options.RootValidity)
            .AsCertificateAuthority(pathLengthConstraint: options.IntermediateName != null ? 1 : 0));

        LogCreatedRootCa(root.SerialNumber);

        // Determine the issuer for the leaf
        X509Certificate2 leafIssuer;
        X509Certificate2? intermediate = null;

        if (options.IntermediateName != null)
        {
            // Create intermediate CA
            intermediate = CertificateFactory.CreateCertificate(o => o
                .WithSubjectName(options.IntermediateName)
                .WithKeyAlgorithm(options.KeyAlgorithm)
                .WithKeySize(options.KeySize ?? GetDefaultKeySize(options.KeyAlgorithm))
                .WithValidity(options.IntermediateValidity)
                .AsCertificateAuthority(pathLengthConstraint: 0)
                .SignedBy(root));

            LogCreatedIntermediateCa(intermediate.SerialNumber);

            leafIssuer = intermediate;
        }
        else
        {
            leafIssuer = root;
        }

        // Create leaf certificate
        var leafOptions = new CertificateOptions()
            .WithSubjectName(options.LeafName)
            .WithKeyAlgorithm(options.KeyAlgorithm)
            .WithKeySize(options.KeySize ?? GetDefaultKeySize(options.KeyAlgorithm))
            .WithValidity(options.LeafValidity)
            .WithKeyUsage(X509KeyUsageFlags.DigitalSignature)
            .SignedBy(leafIssuer);

        if (options.LeafEnhancedKeyUsages != null)
        {
            foreach (var eku in options.LeafEnhancedKeyUsages)
            {
                leafOptions.WithEnhancedKeyUsages(eku);
            }
        }

        var leaf = CertificateFactory.CreateCertificate(o =>
        {
            o.SubjectName = leafOptions.SubjectName;
            o.KeyAlgorithm = leafOptions.KeyAlgorithm;
            o.KeySize = leafOptions.KeySize;
            o.Validity = leafOptions.Validity;
            o.KeyUsage = leafOptions.KeyUsage;
            o.Issuer = leafOptions.Issuer;
            o.EnhancedKeyUsages = leafOptions.EnhancedKeyUsages;
        });

        LogCreatedLeafCertificate(leaf.Subject);

        // Optionally strip private keys from root and intermediate
        if (options.LeafOnlyPrivateKey)
        {
            var rootPublic = CreatePublicOnlyCertificate(root);
            root.Dispose();
            root = rootPublic;

            if (intermediate != null)
            {
                var intermediatePublic = CreatePublicOnlyCertificate(intermediate);
                intermediate.Dispose();
                intermediate = intermediatePublic;
            }
        }

        // Build result collection in configured order
        if (options.LeafFirst)
        {
            result.Add(leaf);
            if (intermediate != null)
            {
                result.Add(intermediate);
            }
            result.Add(root);
        }
        else
        {
            result.Add(root);
            if (intermediate != null)
            {
                result.Add(intermediate);
            }
            result.Add(leaf);
        }

        stopwatch.Stop();
        LogCertificateChainCreatedSuccessfully(result.Count, stopwatch.ElapsedMilliseconds);

        return result;
    }

    private static X509Certificate2 CreatePublicOnlyCertificate(X509Certificate2 certificate)
    {
        return X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
    }

    private static int GetDefaultKeySize(KeyAlgorithm algorithm)
    {
        return algorithm switch
        {
            KeyAlgorithm.RSA => 2048,
            KeyAlgorithm.ECDSA => 256,
            KeyAlgorithm.MLDSA => 65,
            _ => 0
        };
    }
}