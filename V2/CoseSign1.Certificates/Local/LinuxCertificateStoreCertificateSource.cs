// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Certificate source that retrieves certificates from Linux/OpenSSL certificate stores.
/// Supports PEM format files and common Linux certificate store locations.
/// This class is intended for use on Linux, FreeBSD, and macOS systems.
/// </summary>
/// <remarks>
/// On non-Unix systems, some file system operations may not work as expected.
/// </remarks>
public class LinuxCertificateStoreCertificateSource : CertificateSourceBase
{
    private readonly X509Certificate2 _certificate;

    /// <summary>
    /// Common OpenSSL and Linux certificate store paths.
    /// </summary>
    public static readonly string[] DefaultCertificateStorePaths = new[]
    {
        "/etc/ssl/certs",                    // Debian/Ubuntu system CA certificates
        "/etc/pki/tls/certs",                // Red Hat/CentOS system CA certificates
        "/etc/ssl",                          // OpenSSL default
        "/etc/pki/ca-trust/extracted/pem",   // Red Hat/Fedora CA trust
        "/usr/local/share/ca-certificates",  // User-added CA certificates
        "/var/lib/ca-certificates"           // Arch Linux
    };

    /// <summary>
    /// Initializes a new instance by finding a certificate by thumbprint in default store paths.
    /// </summary>
    /// <param name="thumbprint">Certificate thumbprint (hex string)</param>
    /// <param name="storePaths">Optional custom certificate store paths. If null, uses DefaultCertificateStorePaths.</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder for automatic chain building.</param>
    public LinuxCertificateStoreCertificateSource(
        string thumbprint,
        IEnumerable<string>? storePaths = null,
        ICertificateChainBuilder? chainBuilder = null)
        : this(
            (paths) => FindCertificateByThumbprint(paths, thumbprint)
                ?? throw new InvalidOperationException($"Certificate with thumbprint '{thumbprint}' not found in any certificate store"),
            storePaths,
            chainBuilder)
    {
    }

    /// <summary>
    /// Initializes a new instance by finding a certificate by subject name in default store paths.
    /// </summary>
    /// <param name="subjectName">Certificate subject name (or part of it)</param>
    /// <param name="storePaths">Optional custom certificate store paths. If null, uses DefaultCertificateStorePaths.</param>
    /// <param name="validOnly">If true, only returns valid certificates</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder for automatic chain building.</param>
    public LinuxCertificateStoreCertificateSource(
        string subjectName,
        IEnumerable<string>? storePaths,
        bool validOnly,
        ICertificateChainBuilder? chainBuilder = null)
        : this(
            (paths) => FindCertificateBySubjectName(paths, subjectName, validOnly)
                ?? throw new InvalidOperationException($"Certificate with subject name containing '{subjectName}' not found in any certificate store"),
            storePaths,
            chainBuilder)
    {
    }

    /// <summary>
    /// Initializes a new instance with a custom certificate finder predicate.
    /// </summary>
    /// <param name="predicate">Predicate to find the desired certificate</param>
    /// <param name="storePaths">Optional custom certificate store paths. If null, uses DefaultCertificateStorePaths.</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder for automatic chain building.</param>
    public LinuxCertificateStoreCertificateSource(
        Func<X509Certificate2, bool> predicate,
        IEnumerable<string>? storePaths = null,
        ICertificateChainBuilder? chainBuilder = null)
        : this(
            (paths) => FindCertificateByPredicate(paths, predicate)
                ?? throw new InvalidOperationException("No certificate matching the predicate found in any certificate store"),
            storePaths,
            chainBuilder)
    {
    }

    /// <summary>
    /// Initializes a new instance from separate certificate and private key files (common Linux pattern).
    /// </summary>
    /// <param name="certificateFilePath">Path to the certificate file (.pem, .crt)</param>
    /// <param name="privateKeyFilePath">Path to the private key file (.key, .pem)</param>
    /// <param name="keyStorageFlags">Flags controlling how the private key is stored</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, uses X509ChainBuilder for automatic chain building.</param>
    public LinuxCertificateStoreCertificateSource(
        string certificateFilePath,
        string privateKeyFilePath,
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.MachineKeySet,
        ICertificateChainBuilder? chainBuilder = null)
        : base(chainBuilder ?? new X509ChainBuilder())
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateFilePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyFilePath);

        if (!File.Exists(certificateFilePath))
        {
            throw new FileNotFoundException($"Certificate file not found: {certificateFilePath}", certificateFilePath);
        }

        if (!File.Exists(privateKeyFilePath))
        {
            throw new FileNotFoundException($"Private key file not found: {privateKeyFilePath}", privateKeyFilePath);
        }

        // Load certificate and private key separately, then combine them
        var cert = X509CertificateLoader.LoadCertificateFromFile(certificateFilePath);
        var keyPem = File.ReadAllText(privateKeyFilePath);
        
        // Try to parse as RSA key first, then EC if that fails
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(keyPem);
            _certificate = cert.CopyWithPrivateKey(rsa);
        }
        catch (CryptographicException)
        {
            try
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(keyPem);
                _certificate = cert.CopyWithPrivateKey(ecdsa);
            }
            catch (CryptographicException ex)
            {
                cert.Dispose();
                throw new InvalidOperationException($"Unable to import private key from {privateKeyFilePath}. The key format is not supported or the key is invalid.", ex);
            }
        }
        
        // Dispose the certificate without private key since we created a new one with the key
        cert.Dispose();
    }

    /// <summary>
    /// Private constructor that performs the actual certificate retrieval from store paths.
    /// </summary>
    private LinuxCertificateStoreCertificateSource(
        Func<IEnumerable<string>, X509Certificate2> certificateFinder,
        IEnumerable<string>? storePaths,
        ICertificateChainBuilder? chainBuilder)
        : base(chainBuilder ?? new X509ChainBuilder())
    {
        var paths = storePaths ?? DefaultCertificateStorePaths.Where(Directory.Exists);
        _certificate = certificateFinder(paths);
    }

    /// <inheritdoc/>
    public override X509Certificate2 GetSigningCertificate() => _certificate;

    /// <inheritdoc/>
    public override bool HasPrivateKey => _certificate.HasPrivateKey;

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _certificate?.Dispose();
        }
        base.Dispose(disposing);
    }

    /// <summary>
    /// Finds a certificate by thumbprint in the specified store paths.
    /// </summary>
    private static X509Certificate2? FindCertificateByThumbprint(IEnumerable<string> storePaths, string thumbprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(thumbprint);

        // Normalize thumbprint: remove whitespace and convert to uppercase
        string normalizedThumbprint = thumbprint.Replace(" ", "").Replace(":", "").ToUpperInvariant();

        foreach (var path in storePaths)
        {
            if (!Directory.Exists(path))
            {
                continue;
            }

            foreach (var certFile in EnumerateCertificateFiles(path))
            {
                try
                {
                    var cert = X509CertificateLoader.LoadCertificateFromFile(certFile);
                    if (cert.Thumbprint.Equals(normalizedThumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        return cert;
                    }
                    cert.Dispose();
                }
                catch (CryptographicException)
                {
                    // Skip files that can't be parsed as valid certificates
                }
                catch (IOException)
                {
                    // Skip files that can't be read
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Finds a certificate by subject name in the specified store paths.
    /// </summary>
    private static X509Certificate2? FindCertificateBySubjectName(IEnumerable<string> storePaths, string subjectName, bool validOnly)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectName);

        var candidates = new List<X509Certificate2>();

        foreach (var path in storePaths)
        {
            if (!Directory.Exists(path))
            {
                continue;
            }

            foreach (var certFile in EnumerateCertificateFiles(path))
            {
                try
                {
                    var cert = X509CertificateLoader.LoadCertificateFromFile(certFile);
                    if (cert.Subject.Contains(subjectName, StringComparison.OrdinalIgnoreCase))
                    {
                        candidates.Add(cert);
                    }
                    else
                    {
                        cert.Dispose();
                    }
                }
                catch (CryptographicException)
                {
                    // Skip files that can't be parsed as valid certificates
                }
                catch (IOException)
                {
                    // Skip files that can't be read
                }
            }
        }

        if (validOnly)
        {
            var now = DateTime.Now;
            var validCandidates = candidates.Where(c => c.NotBefore <= now && c.NotAfter >= now).ToList();
            
            // Dispose invalid candidates
            foreach (var invalid in candidates.Except(validCandidates))
            {
                invalid.Dispose();
            }
            
            candidates = validCandidates;
        }

        // Prefer certificates with private keys
        var result = candidates.FirstOrDefault(c => c.HasPrivateKey) ?? candidates.FirstOrDefault();
        
        // Dispose the ones we're not using
        foreach (var cert in candidates.Where(c => c != result))
        {
            cert.Dispose();
        }

        return result;
    }

    /// <summary>
    /// Finds a certificate using a predicate in the specified store paths.
    /// </summary>
    private static X509Certificate2? FindCertificateByPredicate(IEnumerable<string> storePaths, Func<X509Certificate2, bool> predicate)
    {
        ArgumentNullException.ThrowIfNull(predicate);

        foreach (var path in storePaths)
        {
            if (!Directory.Exists(path))
            {
                continue;
            }

            foreach (var certFile in EnumerateCertificateFiles(path))
            {
                try
                {
                    var cert = X509CertificateLoader.LoadCertificateFromFile(certFile);
                    if (predicate(cert))
                    {
                        return cert;
                    }
                    cert.Dispose();
                }
                catch (CryptographicException)
                {
                    // Skip files that can't be parsed as valid certificates
                }
                catch (IOException)
                {
                    // Skip files that can't be read
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Enumerates certificate files in the specified directory.
    /// Supports .pem, .crt, .cer extensions.
    /// </summary>
    private static IEnumerable<string> EnumerateCertificateFiles(string directory)
    {
        var extensions = new[] { ".pem", ".crt", ".cer" };
        
        foreach (var ext in extensions)
        {
            foreach (var file in Directory.EnumerateFiles(directory, $"*{ext}", SearchOption.TopDirectoryOnly))
            {
                yield return file;
            }
        }
    }
}
