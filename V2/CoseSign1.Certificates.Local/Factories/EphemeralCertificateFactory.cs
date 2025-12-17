// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Factory for creating ephemeral (in-memory) certificates.
/// </summary>
/// <remarks>
/// <para>
/// Creates X.509 certificates with configurable options including algorithm,
/// key size, validity period, extensions, and certificate chains.
/// </para>
/// <para>
/// Certificates created by this factory:
/// </para>
/// <list type="bullet">
/// <item>Are generated entirely in memory</item>
/// <item>Have private keys that cannot be exported by default</item>
/// <item>Are suitable for testing, development, and ephemeral signing</item>
/// <item>Should NOT be used for long-term production keys without proper key management</item>
/// </list>
/// </remarks>
public class EphemeralCertificateFactory : ICertificateFactory
{
    private readonly ILogger<EphemeralCertificateFactory> Logger;

    /// <summary>
    /// Tracks generated keys by certificate serial number for chain signing scenarios.
    /// Serial number is used because it's known before certificate creation and avoids
    /// accessing certificate properties that may fail for certain algorithms like ML-DSA.
    /// </summary>
    private readonly ConcurrentDictionary<string, IGeneratedKey> GeneratedKeys = new();

    /// <inheritdoc />
    public IPrivateKeyProvider KeyProvider { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="EphemeralCertificateFactory"/> class
    /// with the default software key provider.
    /// </summary>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public EphemeralCertificateFactory(ILogger<EphemeralCertificateFactory>? logger = null)
        : this(new SoftwareKeyProvider(), logger)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EphemeralCertificateFactory"/> class
    /// with a custom key provider.
    /// </summary>
    /// <param name="keyProvider">The key provider to use for key generation.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public EphemeralCertificateFactory(IPrivateKeyProvider keyProvider, ILogger<EphemeralCertificateFactory>? logger = null)
    {
        KeyProvider = keyProvider ?? throw new ArgumentNullException(nameof(keyProvider));
        Logger = logger ?? NullLogger<EphemeralCertificateFactory>.Instance;
    }

    /// <inheritdoc />
    public X509Certificate2 CreateCertificate()
    {
        return CreateCertificate(_ => { });
    }

    /// <inheritdoc />
    public X509Certificate2 CreateCertificate(Action<CertificateOptions> configure)
    {
        if (configure == null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        var options = new CertificateOptions();
        configure(options);

        return CreateCertificateInternal(options);
    }

    /// <inheritdoc />
    public async Task<X509Certificate2> CreateCertificateAsync(
        Action<CertificateOptions> configure,
        CancellationToken cancellationToken = default)
    {
        if (configure == null)
        {
            throw new ArgumentNullException(nameof(configure));
        }

        var options = new CertificateOptions();
        configure(options);

        var stopwatch = Stopwatch.StartNew();

        Logger.LogDebug(
            "Starting async certificate creation. Subject: {Subject}, Algorithm: {Algorithm}",
            options.SubjectName,
            options.KeyAlgorithm);

        // Generate key asynchronously (useful for HSM/TPM providers)
        var key = await KeyProvider.GenerateKeyAsync(options.KeyAlgorithm, options.KeySize, cancellationToken)
            .ConfigureAwait(false);

        try
        {
            var cert = CreateCertificateWithKey(options, key);

            stopwatch.Stop();

            Logger.LogDebug(
                "Async certificate created successfully. Thumbprint: {Thumbprint}, ElapsedMs: {ElapsedMs}",
                cert.Thumbprint,
                stopwatch.ElapsedMilliseconds);

            return cert;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private X509Certificate2 CreateCertificateInternal(CertificateOptions options)
    {
        var stopwatch = Stopwatch.StartNew();

        Logger.LogDebug(
            "Starting certificate creation. Subject: {Subject}, Algorithm: {Algorithm}, KeySize: {KeySize}",
            options.SubjectName,
            options.KeyAlgorithm,
            options.KeySize ?? GetDefaultKeySize(options.KeyAlgorithm));

        if (!KeyProvider.SupportsAlgorithm(options.KeyAlgorithm))
        {
            throw new NotSupportedException(
                $"Key provider '{KeyProvider.ProviderName}' does not support algorithm '{options.KeyAlgorithm}'");
        }

        var key = KeyProvider.GenerateKey(options.KeyAlgorithm, options.KeySize);

        try
        {
            var cert = CreateCertificateWithKey(options, key);

            stopwatch.Stop();

            Logger.LogDebug(
                "Certificate created successfully. Thumbprint: {Thumbprint}, ElapsedMs: {ElapsedMs}",
                cert.Thumbprint,
                stopwatch.ElapsedMilliseconds);

            return cert;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private X509Certificate2 CreateCertificateWithKey(CertificateOptions options, IGeneratedKey key)
    {
        // Get hash algorithm (ML-DSA ignores this but RSA/ECDSA need it)
        var hashAlgorithm = GetHashAlgorithmName(options.HashAlgorithm);

        // Create certificate request using the uniform IGeneratedKey abstraction
        var request = key.CreateCertificateRequest(options.SubjectName, hashAlgorithm);

        // Add basic constraints
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                options.IsCertificateAuthority,
                options.IsCertificateAuthority,
                options.PathLengthConstraint,
                critical: true));

        // Add key usage
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(options.KeyUsage, critical: true));

        // Add Authority Key Identifier if signed by issuer
        if (options.Issuer != null)
        {
            AddAuthorityKeyIdentifier(request, options.Issuer);
        }

        // Add Subject Alternative Names
        AddSubjectAlternativeNames(request, options);

        // Add Enhanced Key Usages
        AddEnhancedKeyUsages(request, options);

        // Add Subject Key Identifier
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        // Add custom extensions
        if (options.CustomExtensions != null)
        {
            foreach (var ext in options.CustomExtensions)
            {
                request.CertificateExtensions.Add(ext);
            }
        }

        // Calculate validity
        var notBefore = options.NotBefore;
        var notAfter = options.NotAfter;

        // Constrain to issuer validity if present
        if (options.Issuer != null)
        {
            if (notBefore < options.Issuer.NotBefore)
            {
                notBefore = new DateTimeOffset(options.Issuer.NotBefore);
            }
            if (notAfter > options.Issuer.NotAfter)
            {
                notAfter = new DateTimeOffset(options.Issuer.NotAfter);
            }
        }

        // Generate serial number for the certificate
        var serial = GenerateSerialNumber();

        // Create certificate using our signature generator (works for all algorithms including ML-DSA)
        X509Certificate2 cert;
        if (options.Issuer != null)
        {
            cert = CreateSignedCertificate(request, options.Issuer, key, notBefore, notAfter, serial);
        }
        else
        {
            // For self-signed, use Create() with our own signature generator instead of CreateSelfSigned()
            // This gives us control over the serial number and works uniformly for all algorithms
            cert = CreateSelfSignedCertificate(request, key, notBefore, notAfter, serial);
        }

        // Track the generated key by certificate serial number for chain signing scenarios
        // Use the certificate's SerialNumber property which is the canonical big-endian hex representation
        GeneratedKeys[cert.SerialNumber] = key;

        return cert;
    }

    private static HashAlgorithmName GetHashAlgorithmName(CertificateHashAlgorithm hashAlgorithm)
    {
        return hashAlgorithm switch
        {
            CertificateHashAlgorithm.SHA256 => HashAlgorithmName.SHA256,
            CertificateHashAlgorithm.SHA384 => HashAlgorithmName.SHA384,
            CertificateHashAlgorithm.SHA512 => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256
        };
    }

    private X509Certificate2 CreateSelfSignedCertificate(
        CertificateRequest request,
        IGeneratedKey key,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        byte[] serial)
    {
        // Use Create() with our signature generator instead of CreateSelfSigned()
        // This allows us to control the serial number and works uniformly for all algorithms
        X509Certificate2 certWithoutKey = request.Create(
            request.SubjectName,
            key.SignatureGenerator,
            notBefore,
            notAfter,
            serial);

        // Copy private key to the certificate
        using (certWithoutKey)
        {
            return key.CopyPrivateKeyTo(certWithoutKey);
        }
    }

    private X509Certificate2 CreateSignedCertificate(
        CertificateRequest request,
        X509Certificate2 issuer,
        IGeneratedKey subjectKey,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        byte[] serial)
    {
        X509Certificate2 certWithoutKey;

        // Look up the issuer's key from our tracked keys by serial number
        string issuerSerialKey = issuer.SerialNumber;
        if (GeneratedKeys.TryGetValue(issuerSerialKey, out var issuerKey))
        {
            // Use the issuer's SignatureGenerator for signing (works for RSA, ECDSA, ML-DSA)
            certWithoutKey = request.Create(issuer.SubjectName, issuerKey.SignatureGenerator, notBefore, notAfter, serial);
        }
        else
        {
            // Issuer wasn't created by this factory - use the certificate's embedded key (RSA/ECDSA only)
            certWithoutKey = request.Create(issuer, notBefore, notAfter, serial);
        }

        // Copy private key to created certificate using the uniform abstraction
        using (certWithoutKey)
        {
            return subjectKey.CopyPrivateKeyTo(certWithoutKey);
        }
    }

    private static void AddAuthorityKeyIdentifier(CertificateRequest request, X509Certificate2 issuer)
    {
        var skiExtension = issuer.Extensions
            .OfType<X509SubjectKeyIdentifierExtension>()
            .FirstOrDefault();

        if (skiExtension?.RawData == null)
        {
            throw new ArgumentException(
                "Issuer certificate must have a Subject Key Identifier extension",
                nameof(issuer));
        }

        // Extract the key identifier value from the SKI extension
        // SKI extension RawData format: 04 14 <key_id>
        var skiRawData = skiExtension.RawData;
        var segment = new ArraySegment<byte>(skiRawData, 2, skiRawData.Length - 2);

        // Build Authority Key Identifier extension
        // AKI format: 30 16 80 14 <key_id>
        var akiData = new byte[segment.Count + 4];
        akiData[0] = 0x30; // SEQUENCE
        akiData[1] = 0x16; // Length (22 bytes: 04 14 + 20-byte key id)
        akiData[2] = 0x80; // Context-specific tag for keyIdentifier [0]
        akiData[3] = 0x14; // Length of key identifier (20 bytes)
        segment.CopyTo(akiData, 4);

        request.CertificateExtensions.Add(
            new X509Extension("2.5.29.35", akiData, critical: false));
    }

    private static void AddSubjectAlternativeNames(CertificateRequest request, CertificateOptions options)
    {
        var sanBuilder = new SubjectAlternativeNameBuilder();

        if (options.SubjectAlternativeNames != null && options.SubjectAlternativeNames.Count > 0)
        {
            foreach (var (type, value) in options.SubjectAlternativeNames)
            {
                switch (type.ToLowerInvariant())
                {
                    case "dns":
                        sanBuilder.AddDnsName(value);
                        break;
                    case "email":
                        sanBuilder.AddEmailAddress(value);
                        break;
                    case "uri":
                        sanBuilder.AddUri(new Uri(value));
                        break;
                    default:
                        throw new ArgumentException($"Unsupported SAN type: {type}");
                }
            }
        }
        else
        {
            // Default: add DNS name based on subject
            var cn = ExtractCommonName(options.SubjectName);
            if (!string.IsNullOrEmpty(cn))
            {
                // Sanitize for DNS name
                var dnsName = cn.Replace(":", "").Replace(" ", "");
                if (dnsName.Length > 40)
                {
                    dnsName = dnsName.Substring(0, 39);
                }
                sanBuilder.AddDnsName(dnsName);
            }
        }

        request.CertificateExtensions.Add(sanBuilder.Build());
    }

    private static void AddEnhancedKeyUsages(CertificateRequest request, CertificateOptions options)
    {
        var oids = new OidCollection();

        if (options.EnhancedKeyUsages != null && options.EnhancedKeyUsages.Count > 0)
        {
            foreach (var eku in options.EnhancedKeyUsages)
            {
                oids.Add(new Oid(eku));
            }
        }
        else
        {
            // Default EKUs for code signing
            oids.Add(new Oid("1.3.6.1.5.5.7.3.3")); // Code Signing
        }

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(oids, critical: false));
    }

    private static string ExtractCommonName(string subjectName)
    {
        // Simple CN extraction - handles "CN=Name" or "CN=Name, O=Org, ..."
        if (subjectName.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
        {
            var endIndex = subjectName.IndexOf(',');
            return endIndex > 0
                ? subjectName.Substring(3, endIndex - 3)
                : subjectName.Substring(3);
        }
        return subjectName;
    }

    private static byte[] GenerateSerialNumber()
    {
        // Use a GUID for guaranteed uniqueness across all scenarios including
        // parallel test execution and multiple factory instances.
        // Take 16 bytes from the GUID - X.509 serial numbers can be up to 20 bytes.
        return Guid.NewGuid().ToByteArray();
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

    /// <summary>
    /// Gets the generated key associated with a certificate created by this factory.
    /// </summary>
    /// <param name="certificate">The certificate to look up.</param>
    /// <returns>The generated key if found, null otherwise.</returns>
    /// <remarks>
    /// This is useful for scenarios where you need the <see cref="X509SignatureGenerator"/>
    /// for a certificate created by this factory, such as signing child certificates
    /// in a chain or signing COSE messages.
    /// </remarks>
    public IGeneratedKey? GetGeneratedKey(X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            return null;
        }

        // Look up by serial number (our tracking key)
        string serialKey = certificate.SerialNumber;
        GeneratedKeys.TryGetValue(serialKey, out var key);
        return key;
    }

    /// <summary>
    /// Releases tracked keys for certificates that are no longer needed.
    /// </summary>
    /// <param name="certificate">The certificate whose key should be released.</param>
    /// <returns>True if a key was found and removed; otherwise, false.</returns>
    public bool ReleaseKey(X509Certificate2 certificate)
    {
        if (certificate == null)
        {
            return false;
        }

        // Look up by serial number (our tracking key)
        string serialKey = certificate.SerialNumber;
        if (GeneratedKeys.TryRemove(serialKey, out var key))
        {
            key.Dispose();
            return true;
        }

        return false;
    }
}