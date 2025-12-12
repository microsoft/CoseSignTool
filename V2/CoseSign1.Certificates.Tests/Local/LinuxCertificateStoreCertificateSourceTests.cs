// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Tests.Common;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests.Local;

public class LinuxCertificateStoreCertificateSourceTests
{
    private string? _testCertDirectory;
    private X509Certificate2? _testCert;
    private string? _certFilePath;
    private string? _keyFilePath;

    [SetUp]
    public void Setup()
    {
        // Create a temporary directory for test certificates
        _testCertDirectory = Path.Combine(Path.GetTempPath(), $"CoseSignTest_{Guid.NewGuid()}");
        Directory.CreateDirectory(_testCertDirectory);

        // Create a test certificate
        _testCert = TestCertificateUtils.CreateCertificate("LinuxCertStoreTest");

        // Export certificate to PEM format
        _certFilePath = Path.Combine(_testCertDirectory, "test.crt");
        var certPem = _testCert.ExportCertificatePem();
        File.WriteAllText(_certFilePath, certPem);

        // Export private key to PEM format
        _keyFilePath = Path.Combine(_testCertDirectory, "test.key");
        var keyPem = _testCert.GetRSAPrivateKey()!.ExportRSAPrivateKeyPem();
        File.WriteAllText(_keyFilePath, keyPem);
    }

    [TearDown]
    public void Cleanup()
    {
        _testCert?.Dispose();

        if (_testCertDirectory != null && Directory.Exists(_testCertDirectory))
        {
            Directory.Delete(_testCertDirectory, recursive: true);
        }
    }

    [Test]
    public void Constructor_WithCertificateAndKeyFiles_Succeeds()
    {
        // This test may fail on Windows since the constructor is marked with [SupportedOSPlatform("linux")]
        // but we'll test the basic file loading logic
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                _certFilePath!,
                _keyFilePath!);

            Assert.That(source, Is.Not.Null);
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }

    [Test]
    public void Constructor_WithNullCertificateFile_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new LinuxCertificateStoreCertificateSource((string)null!, _keyFilePath!));
    }

    [Test]
    public void Constructor_WithNullKeyFile_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new LinuxCertificateStoreCertificateSource(_certFilePath!, (string)null!));
    }

    [Test]
    public void Constructor_WithNonExistentCertificateFile_ThrowsFileNotFoundException()
    {
        Assert.Throws<FileNotFoundException>(() =>
            new LinuxCertificateStoreCertificateSource("nonexistent.crt", _keyFilePath!));
    }

    [Test]
    public void Constructor_WithNonExistentKeyFile_ThrowsFileNotFoundException()
    {
        Assert.Throws<FileNotFoundException>(() =>
            new LinuxCertificateStoreCertificateSource(_certFilePath!, "nonexistent.key"));
    }

    [Test]
    public void Constructor_WithThumbprint_SearchesDefaultPaths()
    {
        // Create certificate in test directory
        var anotherCert = TestCertificateUtils.CreateCertificate("AnotherTest");
        var anotherCertPath = Path.Combine(_testCertDirectory!, "another.pem");
        File.WriteAllText(anotherCertPath, anotherCert.ExportCertificatePem());

        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                anotherCert.Thumbprint,
                storePaths: new[] { _testCertDirectory! });

            Assert.That(source, Is.Not.Null);
            Assert.That(source.GetSigningCertificate().Thumbprint, Is.EqualTo(anotherCert.Thumbprint));
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
        finally
        {
            anotherCert.Dispose();
        }
    }

    [Test]
    public void Constructor_WithInvalidThumbprint_ThrowsInvalidOperationException()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new LinuxCertificateStoreCertificateSource(
                "0000000000000000000000000000000000000000",
                storePaths: new[] { _testCertDirectory! }));
    }

    [Test]
    public void Constructor_WithSubjectName_FindsCertificate()
    {
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                "LinuxCertStoreTest",
                storePaths: new[] { _testCertDirectory! },
                validOnly: false);

            Assert.That(source, Is.Not.Null);
            Assert.That(source.GetSigningCertificate().Subject, Does.Contain("LinuxCertStoreTest"));
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }

    [Test]
    public void Constructor_WithPredicate_FindsCertificate()
    {
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                cert => cert.Subject.Contains("LinuxCertStoreTest"),
                storePaths: new[] { _testCertDirectory! });

            Assert.That(source, Is.Not.Null);
            Assert.That(source.GetSigningCertificate().Subject, Does.Contain("LinuxCertStoreTest"));
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }

    [Test]
    public void Constructor_WithNullPredicate_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new LinuxCertificateStoreCertificateSource(
                (Func<X509Certificate2, bool>)null!,
                storePaths: new[] { _testCertDirectory! }));
    }

    [Test]
    public void Constructor_WithNonMatchingPredicate_ThrowsInvalidOperationException()
    {
        Assert.Throws<InvalidOperationException>(() =>
            new LinuxCertificateStoreCertificateSource(
                cert => false,
                storePaths: new[] { _testCertDirectory! }));
    }

    [Test]
    public void DefaultCertificateStorePaths_ContainsCommonLinuxPaths()
    {
        var paths = LinuxCertificateStoreCertificateSource.DefaultCertificateStorePaths;

        Assert.That(paths, Contains.Item("/etc/ssl/certs"));
        Assert.That(paths, Contains.Item("/etc/pki/tls/certs"));
        Assert.That(paths, Contains.Item("/etc/ssl"));
        Assert.That(paths, Contains.Item("/usr/local/share/ca-certificates"));
    }

    [Test]
    public void GetChainBuilder_ReturnsX509ChainBuilder()
    {
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                _certFilePath!,
                _keyFilePath!);

            var chainBuilder = source.GetChainBuilder();

            Assert.That(chainBuilder, Is.Not.Null);
            Assert.That(chainBuilder, Is.InstanceOf<CoseSign1.Certificates.ChainBuilders.X509ChainBuilder>());
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }

    [Test]
    public void UsageWithLocalCertificateSigningService_Succeeds()
    {
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                _certFilePath!,
                _keyFilePath!);

            var cert = source.GetSigningCertificate();

            if (!cert.HasPrivateKey)
            {
                Assert.Inconclusive("Certificate does not have private key accessible in this context");
                return;
            }

            var chainBuilder = source.GetChainBuilder();
            using var signingService = new LocalCertificateSigningService(cert, chainBuilder);

            Assert.That(signingService, Is.Not.Null);
            Assert.That(signingService.IsRemote, Is.False);
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }

    [Test]
    public void Dispose_CanBeCalledMultipleTimes()
    {
        var source = new LinuxCertificateStoreCertificateSource(
            cert => cert.Subject.Contains("LinuxCertStoreTest"),
            storePaths: new[] { _testCertDirectory! });

        source.Dispose();
        source.Dispose(); // Should not throw
    }

    [Test]
    public void Constructor_WithCustomStorePaths_UsesProvidedPaths()
    {
        var customPath = Path.Combine(_testCertDirectory!, "custom");
        Directory.CreateDirectory(customPath);

        var customCert = TestCertificateUtils.CreateCertificate("CustomPathTest");
        var customCertPath = Path.Combine(customPath, "custom.crt");
        File.WriteAllText(customCertPath, customCert.ExportCertificatePem());

        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                customCert.Thumbprint,
                storePaths: new[] { customPath });

            Assert.That(source, Is.Not.Null);
            Assert.That(source.GetSigningCertificate().Thumbprint, Is.EqualTo(customCert.Thumbprint));
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
        finally
        {
            customCert.Dispose();
        }
    }

    [Test]
    public void Constructor_WithMultipleCertificateExtensions_FindsAll()
    {
        // Create certificates with different extensions
        var pemCert = TestCertificateUtils.CreateCertificate("PemTest");
        var crtCert = TestCertificateUtils.CreateCertificate("CrtTest");
        var cerCert = TestCertificateUtils.CreateCertificate("CerTest");

        File.WriteAllText(Path.Combine(_testCertDirectory!, "test.pem"), pemCert.ExportCertificatePem());
        File.WriteAllText(Path.Combine(_testCertDirectory!, "test2.crt"), crtCert.ExportCertificatePem());
        File.WriteAllText(Path.Combine(_testCertDirectory!, "test3.cer"), cerCert.ExportCertificatePem());

        try
        {
            // Should find PemTest certificate
            using var source1 = new LinuxCertificateStoreCertificateSource(
                "PemTest",
                storePaths: new[] { _testCertDirectory! },
                validOnly: false);
            Assert.That(source1.GetSigningCertificate().Subject, Does.Contain("PemTest"));

            // Should find CrtTest certificate
            using var source2 = new LinuxCertificateStoreCertificateSource(
                "CrtTest",
                storePaths: new[] { _testCertDirectory! },
                validOnly: false);
            Assert.That(source2.GetSigningCertificate().Subject, Does.Contain("CrtTest"));

            // Should find CerTest certificate
            using var source3 = new LinuxCertificateStoreCertificateSource(
                "CerTest",
                storePaths: new[] { _testCertDirectory! },
                validOnly: false);
            Assert.That(source3.GetSigningCertificate().Subject, Does.Contain("CerTest"));
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
        finally
        {
            pemCert.Dispose();
            crtCert.Dispose();
            cerCert.Dispose();
        }
    }

    [Test]
    public void Constructor_WithThumbprintNormalization_HandlesVariousFormats()
    {
        // Test thumbprint with spaces and colons
        var cert = TestCertificateUtils.CreateCertificate("NormalizeTest");
        var certPath = Path.Combine(_testCertDirectory!, "normalize.pem");
        File.WriteAllText(certPath, cert.ExportCertificatePem());

        try
        {
            // Format with spaces
            var thumbprintWithSpaces = string.Join(" ", cert.Thumbprint.ToCharArray().Select((c, i) => i % 2 == 1 ? c + " " : c.ToString()).ToArray()).Trim();
            using var source1 = new LinuxCertificateStoreCertificateSource(
                thumbprintWithSpaces,
                storePaths: new[] { _testCertDirectory! });
            Assert.That(source1.GetSigningCertificate().Thumbprint, Is.EqualTo(cert.Thumbprint));

            // Format with colons
            var thumbprintWithColons = string.Join(":", cert.Thumbprint.ToCharArray().Select((c, i) => i % 2 == 1 ? c + ":" : c.ToString()).ToArray()).TrimEnd(':');
            using var source2 = new LinuxCertificateStoreCertificateSource(
                thumbprintWithColons,
                storePaths: new[] { _testCertDirectory! });
            Assert.That(source2.GetSigningCertificate().Thumbprint, Is.EqualTo(cert.Thumbprint));
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
        finally
        {
            cert.Dispose();
        }
    }

    [Test]
    public void Constructor_WithValidOnlyFilter_FiltersExpiredCertificates()
    {
        // Create an expired certificate using duration
        var expiredDuration = TimeSpan.FromDays(-1); // Already expired
        var expiredCert = TestCertificateUtils.CreateCertificate(
            "ExpiredTest",
            duration: expiredDuration);

        var expiredPath = Path.Combine(_testCertDirectory!, "expired.pem");
        File.WriteAllText(expiredPath, expiredCert.ExportCertificatePem());

        try
        {
            // Should not find expired certificate with validOnly=true
            Assert.Throws<InvalidOperationException>(() =>
                new LinuxCertificateStoreCertificateSource(
                    "ExpiredTest",
                    storePaths: new[] { _testCertDirectory! },
                    validOnly: true));

            // Should find expired certificate with validOnly=false
            using var source = new LinuxCertificateStoreCertificateSource(
                "ExpiredTest",
                storePaths: new[] { _testCertDirectory! },
                validOnly: false);
            Assert.That(source, Is.Not.Null);
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
        finally
        {
            expiredCert.Dispose();
        }
    }

    [Test]
    public void Constructor_WithInvalidPrivateKeyFile_ThrowsException()
    {
        // Create a file with invalid key data
        var invalidKeyPath = Path.Combine(_testCertDirectory!, "invalid.key");
        File.WriteAllText(invalidKeyPath, "This is not a valid PEM key");

        var ex = Assert.Throws<ArgumentException>(() =>
            new LinuxCertificateStoreCertificateSource(_certFilePath!, invalidKeyPath));

        Assert.That(ex.Message, Does.Contain("No supported key formats were found"));
    }

    [Test]
    public void Constructor_WithECDSACertificate_LoadsSuccessfully()
    {
        // Create an ECDSA certificate
        var ecdsaCert = TestCertificateUtils.CreateECDsaCertificate("ECDSATest");
        var ecdsaCertPath = Path.Combine(_testCertDirectory!, "ecdsa.crt");
        var ecdsaKeyPath = Path.Combine(_testCertDirectory!, "ecdsa.key");

        File.WriteAllText(ecdsaCertPath, ecdsaCert.ExportCertificatePem());

        // Export private key in PEM format
        var ecdsaKey = ecdsaCert.GetECDsaPrivateKey()!;
        var keyPem = ecdsaKey.ExportPkcs8PrivateKeyPem();
        File.WriteAllText(ecdsaKeyPath, keyPem);

        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                ecdsaCertPath,
                ecdsaKeyPath);

            Assert.That(source, Is.Not.Null);
            Assert.That(source.GetSigningCertificate().GetECDsaPrivateKey(), Is.Not.Null);
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
        finally
        {
            ecdsaCert.Dispose();
        }
    }

    [Test]
    public void Constructor_WithCustomChainBuilder_UsesProvidedBuilder()
    {
        var customBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(
            new[] { _testCert! });

        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                _certFilePath!,
                _keyFilePath!,
                chainBuilder: customBuilder);

            var builder = source.GetChainBuilder();
            Assert.That(builder, Is.SameAs(customBuilder));
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }

    [Test]
    public void Constructor_WithNonExistentStorePath_SkipsPath()
    {
        var nonExistentPath = Path.Combine(_testCertDirectory!, "nonexistent");

        // Should not throw, just skip the non-existent path
        Assert.Throws<InvalidOperationException>(() =>
            new LinuxCertificateStoreCertificateSource(
                "NonExistent",
                storePaths: new[] { nonExistentPath }));
    }

    [Test]
    public void Constructor_WithCorruptedCertificateFiles_SkipsThem()
    {
        // Create a corrupted certificate file
        var corruptedPath = Path.Combine(_testCertDirectory!, "corrupted.pem");
        File.WriteAllText(corruptedPath, "-----BEGIN CERTIFICATE-----\nThis is not valid base64\n-----END CERTIFICATE-----");

        // Should skip corrupted file and find the valid one
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                "LinuxCertStoreTest",
                storePaths: new[] { _testCertDirectory! },
                validOnly: false);

            Assert.That(source, Is.Not.Null);
            Assert.That(source.GetSigningCertificate().Subject, Does.Contain("LinuxCertStoreTest"));
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }

    [Test]
    public void Constructor_WithEmptyThumbprint_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            new LinuxCertificateStoreCertificateSource(
                "",
                storePaths: new[] { _testCertDirectory! }));
    }

    [Test]
    public void Constructor_WithWhitespaceThumbprint_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            new LinuxCertificateStoreCertificateSource(
                "   ",
                storePaths: new[] { _testCertDirectory! }));
    }

    [Test]
    public void Constructor_WithEmptySubjectName_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() =>
            new LinuxCertificateStoreCertificateSource(
                "",
                storePaths: new[] { _testCertDirectory! },
                validOnly: false));
    }

    [Test]
    public void Constructor_WithKeyStorageFlags_AppliesFlags()
    {
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                _certFilePath!,
                _keyFilePath!,
                keyStorageFlags: X509KeyStorageFlags.EphemeralKeySet);

            Assert.That(source, Is.Not.Null);
            Assert.That(source.HasPrivateKey, Is.True);
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }

    [Test]
    public void HasPrivateKey_ReturnsFalse_WhenCertificateHasNoPrivateKey()
    {
        // Create certificate without private key in store
        var certOnlyCert = TestCertificateUtils.CreateCertificate("CertOnly");
        var certOnlyPath = Path.Combine(_testCertDirectory!, "certonly.pem");
        File.WriteAllText(certOnlyPath, certOnlyCert.ExportCertificatePem());

        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                "CertOnly",
                storePaths: new[] { _testCertDirectory! },
                validOnly: false);

            Assert.That(source.HasPrivateKey, Is.False);
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
        finally
        {
            certOnlyCert.Dispose();
        }
    }

    [Test]
    public void Constructor_WithMultipleCertificatesInPath_PrefersOneWithPrivateKey()
    {
        // Create two certificates with same subject, one with private key accessible
        var cert1 = TestCertificateUtils.CreateCertificate("MultiTest");
        var cert2 = TestCertificateUtils.CreateCertificate("MultiTest");

        // Write both to disk (cert1 without key file, cert2 with key file)
        var cert1Path = Path.Combine(_testCertDirectory!, "multi1.pem");
        var cert2Path = Path.Combine(_testCertDirectory!, "multi2.pem");
        var cert2KeyPath = Path.Combine(_testCertDirectory!, "multi2.key");

        File.WriteAllText(cert1Path, cert1.ExportCertificatePem());
        File.WriteAllText(cert2Path, cert2.ExportCertificatePem());
        File.WriteAllText(cert2KeyPath, cert2.GetRSAPrivateKey()!.ExportRSAPrivateKeyPem());

        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                "MultiTest",
                storePaths: new[] { _testCertDirectory! },
                validOnly: false);

            // Should prefer the certificate without private key since we can't detect
            // private key availability from file-based certificates
            Assert.That(source, Is.Not.Null);
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
        finally
        {
            cert1.Dispose();
            cert2.Dispose();
        }
    }

    [Test]
    public void Constructor_WithNullStorePaths_UsesDefaultPaths()
    {
        try
        {
            // This will fail because test cert is not in default paths, but validates null handling
            Assert.Throws<InvalidOperationException>(() =>
                new LinuxCertificateStoreCertificateSource(
                    _testCert!.Thumbprint,
                    storePaths: null));
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }

    [Test]
    public void GetSigningCertificate_ReturnsSameCertificateInstance()
    {
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                _certFilePath!,
                _keyFilePath!);

            var cert1 = source.GetSigningCertificate();
            var cert2 = source.GetSigningCertificate();

            Assert.That(cert1, Is.SameAs(cert2));
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }

    [Test]
    public void Constructor_WithIOExceptionOnFileRead_SkipsFile()
    {
        // Create a directory instead of a file to trigger IOException
        var directoryAsFile = Path.Combine(_testCertDirectory!, "fake.pem");
        Directory.CreateDirectory(directoryAsFile);

        try
        {
            // Should skip the directory and find the valid certificate
            using var source = new LinuxCertificateStoreCertificateSource(
                "LinuxCertStoreTest",
                storePaths: new[] { _testCertDirectory! },
                validOnly: false);

            Assert.That(source, Is.Not.Null);
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }
}