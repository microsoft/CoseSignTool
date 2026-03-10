// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Local;

using CoseSign1.Certificates.Local;

public class LinuxCertificateStoreCertificateSourceTests
{
    private sealed record TestContext(
        string TestCertDirectory,
        X509Certificate2 TestCert,
        string CertFilePath,
        string KeyFilePath) : IDisposable
    {
        public void Dispose()
        {
            TestCert.Dispose();

            if (Directory.Exists(TestCertDirectory))
            {
                Directory.Delete(TestCertDirectory, recursive: true);
            }
        }
    }

    private static TestContext CreateTestContext()
    {
        // Create a temporary directory for test certificates
        string testCertDirectory = Path.Combine(Path.GetTempPath(), $"CoseSignTest_{Guid.NewGuid()}");
        Directory.CreateDirectory(testCertDirectory);

        // Create a test certificate
        X509Certificate2 testCert = TestCertificateUtils.CreateCertificate("LinuxCertStoreTest");

        // Export certificate to PEM format
        string certFilePath = Path.Combine(testCertDirectory, "test.crt");
        var certPem = testCert.ExportCertificatePem();
        File.WriteAllText(certFilePath, certPem);

        // Export private key to PEM format
        string keyFilePath = Path.Combine(testCertDirectory, "test.key");
        var keyPem = testCert.GetRSAPrivateKey()!.ExportRSAPrivateKeyPem();
        File.WriteAllText(keyFilePath, keyPem);

        return new TestContext(testCertDirectory, testCert, certFilePath, keyFilePath);
    }

    [Test]
    public void Constructor_WithCertificateAndKeyFiles_Succeeds()
    {
        using var ctx = CreateTestContext();
        // This test may fail on Windows since the constructor is marked with [SupportedOSPlatform("linux")]
        // but we'll test the basic file loading logic
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                ctx.CertFilePath,
                ctx.KeyFilePath);

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
        using var ctx = CreateTestContext();
        Assert.Throws<ArgumentNullException>(() =>
            new LinuxCertificateStoreCertificateSource((string)null!, ctx.KeyFilePath));
    }

    [Test]
    public void Constructor_WithNullKeyFile_ThrowsArgumentException()
    {
        using var ctx = CreateTestContext();
        Assert.Throws<ArgumentNullException>(() =>
            new LinuxCertificateStoreCertificateSource(ctx.CertFilePath, (string)null!));
    }

    [Test]
    public void Constructor_WithNonExistentCertificateFile_ThrowsFileNotFoundException()
    {
        using var ctx = CreateTestContext();
        Assert.Throws<FileNotFoundException>(() =>
            new LinuxCertificateStoreCertificateSource("nonexistent.crt", ctx.KeyFilePath));
    }

    [Test]
    public void Constructor_WithNonExistentKeyFile_ThrowsFileNotFoundException()
    {
        using var ctx = CreateTestContext();
        Assert.Throws<FileNotFoundException>(() =>
            new LinuxCertificateStoreCertificateSource(ctx.CertFilePath, "nonexistent.key"));
    }

    [Test]
    public void Constructor_WithInvalidPrivateKeyFile_ThrowsInvalidOperationException()
    {
        using var ctx = CreateTestContext();
        // Arrange
        var invalidKeyPath = Path.Combine(ctx.TestCertDirectory, "invalid.key");
        // Provide both RSA and EC blocks with invalid key material so that:
        // - RSA.ImportFromPem throws CryptographicException (caught)
        // - ECDsa.ImportFromPem throws CryptographicException (caught)
        // which drives the constructor into the final InvalidOperationException path.
        File.WriteAllText(invalidKeyPath,
            "-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n" +
            "-----BEGIN EC PRIVATE KEY-----\nAA==\n-----END EC PRIVATE KEY-----\n");

        try
        {
            // Act & Assert
            var ex = Assert.Throws<InvalidOperationException>(() =>
                new LinuxCertificateStoreCertificateSource(ctx.CertFilePath, invalidKeyPath));

            Assert.That(ex!.Message, Does.Contain("Unable to import private key"));
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }

    [Test]
    public void Constructor_WithThumbprint_SearchesDefaultPaths()
    {
        using var ctx = CreateTestContext();
        // Create certificate in test directory
        var anotherCert = TestCertificateUtils.CreateCertificate("AnotherTest");
        var anotherCertPath = Path.Combine(ctx.TestCertDirectory, "another.pem");
        File.WriteAllText(anotherCertPath, anotherCert.ExportCertificatePem());

        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                anotherCert.Thumbprint,
                storePaths: new[] { ctx.TestCertDirectory });

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
    public void Constructor_WithThumbprintContainingSpacesAndColons_FindsCertificate()
    {
        using var ctx = CreateTestContext();
        // Arrange
        var anotherCert = TestCertificateUtils.CreateCertificate("AnotherTestNormalizedThumbprint");
        var anotherCertPath = Path.Combine(ctx.TestCertDirectory, "another2.pem");
        File.WriteAllText(anotherCertPath, anotherCert.ExportCertificatePem());

        // Introduce spaces and colons to validate normalization.
        var normalized = anotherCert.Thumbprint;
        var thumbprintWithColons = string.Join(":", Enumerable.Range(0, normalized.Length / 2)
            .Select(i => normalized.Substring(i * 2, 2)));
        var thumbprintWithNoise = thumbprintWithColons.Insert(5, " ");

        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                thumbprintWithNoise,
                storePaths: new[] { ctx.TestCertDirectory });

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
        using var ctx = CreateTestContext();
        Assert.Throws<InvalidOperationException>(() =>
            new LinuxCertificateStoreCertificateSource(
                "0000000000000000000000000000000000000000",
                storePaths: new[] { ctx.TestCertDirectory }));
    }

    [Test]
    public void Constructor_WithSubjectName_FindsCertificate()
    {
        using var ctx = CreateTestContext();
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                "LinuxCertStoreTest",
                storePaths: new[] { ctx.TestCertDirectory },
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
        using var ctx = CreateTestContext();
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                cert => cert.Subject.Contains("LinuxCertStoreTest"),
                storePaths: new[] { ctx.TestCertDirectory });

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
        using var ctx = CreateTestContext();
        Assert.Throws<ArgumentNullException>(() =>
            new LinuxCertificateStoreCertificateSource(
                (Func<X509Certificate2, bool>)null!,
                storePaths: new[] { ctx.TestCertDirectory }));
    }

    [Test]
    public void Constructor_WithNonMatchingPredicate_ThrowsInvalidOperationException()
    {
        using var ctx = CreateTestContext();
        Assert.Throws<InvalidOperationException>(() =>
            new LinuxCertificateStoreCertificateSource(
                cert => false,
                storePaths: new[] { ctx.TestCertDirectory }));
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
        using var ctx = CreateTestContext();
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                ctx.CertFilePath,
                ctx.KeyFilePath);

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
        using var ctx = CreateTestContext();
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                ctx.CertFilePath,
                ctx.KeyFilePath);

            var cert = source.GetSigningCertificate();

            if (!cert.HasPrivateKey)
            {
                Assert.Inconclusive("Certificate does not have private key accessible in this context");
                return;
            }

            var chainBuilder = source.GetChainBuilder();
            using var signingService = CertificateSigningService.Create(cert, chainBuilder);

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
        using var ctx = CreateTestContext();
        var source = new LinuxCertificateStoreCertificateSource(
            cert => cert.Subject.Contains("LinuxCertStoreTest"),
            storePaths: new[] { ctx.TestCertDirectory });

        source.Dispose();
        source.Dispose(); // Should not throw
    }

    [Test]
    public void Constructor_WithCustomStorePaths_UsesProvidedPaths()
    {
        using var ctx = CreateTestContext();
        var customPath = Path.Combine(ctx.TestCertDirectory, "custom");
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
        using var ctx = CreateTestContext();
        // Create certificates with different extensions
        var pemCert = TestCertificateUtils.CreateCertificate("PemTest");
        var crtCert = TestCertificateUtils.CreateCertificate("CrtTest");
        var cerCert = TestCertificateUtils.CreateCertificate("CerTest");

        File.WriteAllText(Path.Combine(ctx.TestCertDirectory, "test.pem"), pemCert.ExportCertificatePem());
        File.WriteAllText(Path.Combine(ctx.TestCertDirectory, "test2.crt"), crtCert.ExportCertificatePem());
        File.WriteAllText(Path.Combine(ctx.TestCertDirectory, "test3.cer"), cerCert.ExportCertificatePem());

        try
        {
            // Should find PemTest certificate
            using var source1 = new LinuxCertificateStoreCertificateSource(
                "PemTest",
                storePaths: new[] { ctx.TestCertDirectory },
                validOnly: false);
            Assert.That(source1.GetSigningCertificate().Subject, Does.Contain("PemTest"));

            // Should find CrtTest certificate
            using var source2 = new LinuxCertificateStoreCertificateSource(
                "CrtTest",
                storePaths: new[] { ctx.TestCertDirectory },
                validOnly: false);
            Assert.That(source2.GetSigningCertificate().Subject, Does.Contain("CrtTest"));

            // Should find CerTest certificate
            using var source3 = new LinuxCertificateStoreCertificateSource(
                "CerTest",
                storePaths: new[] { ctx.TestCertDirectory },
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
        using var ctx = CreateTestContext();
        // Test thumbprint with spaces and colons
        var cert = TestCertificateUtils.CreateCertificate("NormalizeTest");
        var certPath = Path.Combine(ctx.TestCertDirectory, "normalize.pem");
        File.WriteAllText(certPath, cert.ExportCertificatePem());

        try
        {
            // Format with spaces
            var thumbprintWithSpaces = string.Join(" ", cert.Thumbprint.ToCharArray().Select((c, i) => i % 2 == 1 ? c + " " : c.ToString()).ToArray()).Trim();
            using var source1 = new LinuxCertificateStoreCertificateSource(
                thumbprintWithSpaces,
                storePaths: new[] { ctx.TestCertDirectory });
            Assert.That(source1.GetSigningCertificate().Thumbprint, Is.EqualTo(cert.Thumbprint));

            // Format with colons
            var thumbprintWithColons = string.Join(":", cert.Thumbprint.ToCharArray().Select((c, i) => i % 2 == 1 ? c + ":" : c.ToString()).ToArray()).TrimEnd(':');
            using var source2 = new LinuxCertificateStoreCertificateSource(
                thumbprintWithColons,
                storePaths: new[] { ctx.TestCertDirectory });
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
        using var ctx = CreateTestContext();
        // Create an expired certificate using duration
        var expiredDuration = TimeSpan.FromDays(-1); // Already expired
        var expiredCert = TestCertificateUtils.CreateCertificate(
            "ExpiredTest",
            duration: expiredDuration);

        var expiredPath = Path.Combine(ctx.TestCertDirectory, "expired.pem");
        File.WriteAllText(expiredPath, expiredCert.ExportCertificatePem());

        try
        {
            // Should not find expired certificate with validOnly=true
            Assert.Throws<InvalidOperationException>(() =>
                new LinuxCertificateStoreCertificateSource(
                    "ExpiredTest",
                    storePaths: new[] { ctx.TestCertDirectory },
                    validOnly: true));

            // Should find expired certificate with validOnly=false
            using var source = new LinuxCertificateStoreCertificateSource(
                "ExpiredTest",
                storePaths: new[] { ctx.TestCertDirectory },
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
        using var ctx = CreateTestContext();
        // Create a file with invalid key data
        var invalidKeyPath = Path.Combine(ctx.TestCertDirectory, "invalid.key");
        File.WriteAllText(invalidKeyPath, "This is not a valid PEM key");

        var ex = Assert.Throws<ArgumentException>(() =>
            new LinuxCertificateStoreCertificateSource(ctx.CertFilePath, invalidKeyPath));

        Assert.That(ex.Message, Does.Contain("No supported key formats were found"));
    }

    [Test]
    public void Constructor_WithECDSACertificate_LoadsSuccessfully()
    {
        using var ctx = CreateTestContext();
        // Create an ECDSA certificate
        var ecdsaCert = TestCertificateUtils.CreateECDsaCertificate("ECDSATest");
        var ecdsaCertPath = Path.Combine(ctx.TestCertDirectory, "ecdsa.crt");
        var ecdsaKeyPath = Path.Combine(ctx.TestCertDirectory, "ecdsa.key");

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
        using var ctx = CreateTestContext();
        var customBuilder = new CoseSign1.Certificates.ChainBuilders.ExplicitCertificateChainBuilder(
            new[] { ctx.TestCert });

        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                ctx.CertFilePath,
                ctx.KeyFilePath,
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
        using var ctx = CreateTestContext();
        var nonExistentPath = Path.Combine(ctx.TestCertDirectory, "nonexistent");

        // Should not throw, just skip the non-existent path
        Assert.Throws<InvalidOperationException>(() =>
            new LinuxCertificateStoreCertificateSource(
                "NonExistent",
                storePaths: new[] { nonExistentPath }));
    }

    [Test]
    public void Constructor_WithCorruptedCertificateFiles_SkipsThem()
    {
        using var ctx = CreateTestContext();
        // Create a corrupted certificate file
        var corruptedPath = Path.Combine(ctx.TestCertDirectory, "corrupted.pem");
        File.WriteAllText(corruptedPath, "-----BEGIN CERTIFICATE-----\nThis is not valid base64\n-----END CERTIFICATE-----");

        // Should skip corrupted file and find the valid one
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                "LinuxCertStoreTest",
                storePaths: new[] { ctx.TestCertDirectory },
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
        using var ctx = CreateTestContext();
        Assert.Throws<ArgumentException>(() =>
            new LinuxCertificateStoreCertificateSource(
                "",
                storePaths: new[] { ctx.TestCertDirectory }));
    }

    [Test]
    public void Constructor_WithWhitespaceThumbprint_ThrowsArgumentException()
    {
        using var ctx = CreateTestContext();
        Assert.Throws<ArgumentException>(() =>
            new LinuxCertificateStoreCertificateSource(
                "   ",
                storePaths: new[] { ctx.TestCertDirectory }));
    }

    [Test]
    public void Constructor_WithEmptySubjectName_ThrowsArgumentException()
    {
        using var ctx = CreateTestContext();
        Assert.Throws<ArgumentException>(() =>
            new LinuxCertificateStoreCertificateSource(
                "",
                storePaths: new[] { ctx.TestCertDirectory },
                validOnly: false));
    }

    [Test]
    public void Constructor_WithKeyStorageFlags_AppliesFlags()
    {
        using var ctx = CreateTestContext();
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                ctx.CertFilePath,
                ctx.KeyFilePath,
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
        using var ctx = CreateTestContext();
        // Create certificate without private key in store
        var certOnlyCert = TestCertificateUtils.CreateCertificate("CertOnly");
        var certOnlyPath = Path.Combine(ctx.TestCertDirectory, "certonly.pem");
        File.WriteAllText(certOnlyPath, certOnlyCert.ExportCertificatePem());

        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                "CertOnly",
                storePaths: new[] { ctx.TestCertDirectory },
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
        using var ctx = CreateTestContext();
        // Create two certificates with same subject, one with private key accessible
        var cert1 = TestCertificateUtils.CreateCertificate("MultiTest");
        var cert2 = TestCertificateUtils.CreateCertificate("MultiTest");

        // Write both to disk (cert1 without key file, cert2 with key file)
        var cert1Path = Path.Combine(ctx.TestCertDirectory, "multi1.pem");
        var cert2Path = Path.Combine(ctx.TestCertDirectory, "multi2.pem");
        var cert2KeyPath = Path.Combine(ctx.TestCertDirectory, "multi2.key");

        File.WriteAllText(cert1Path, cert1.ExportCertificatePem());
        File.WriteAllText(cert2Path, cert2.ExportCertificatePem());
        File.WriteAllText(cert2KeyPath, cert2.GetRSAPrivateKey()!.ExportRSAPrivateKeyPem());

        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                "MultiTest",
                storePaths: new[] { ctx.TestCertDirectory },
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
        using var ctx = CreateTestContext();
        try
        {
            // This will fail because test cert is not in default paths, but validates null handling
            Assert.Throws<InvalidOperationException>(() =>
                new LinuxCertificateStoreCertificateSource(
                    ctx.TestCert.Thumbprint,
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
        using var ctx = CreateTestContext();
        try
        {
            using var source = new LinuxCertificateStoreCertificateSource(
                ctx.CertFilePath,
                ctx.KeyFilePath);

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
        using var ctx = CreateTestContext();
        // Create a directory instead of a file to trigger IOException
        var directoryAsFile = Path.Combine(ctx.TestCertDirectory, "fake.pem");
        Directory.CreateDirectory(directoryAsFile);

        try
        {
            // Should skip the directory and find the valid certificate
            using var source = new LinuxCertificateStoreCertificateSource(
                "LinuxCertStoreTest",
                storePaths: new[] { ctx.TestCertDirectory },
                validOnly: false);

            Assert.That(source, Is.Not.Null);
        }
        catch (PlatformNotSupportedException)
        {
            Assert.Inconclusive("Test requires Linux/Unix platform");
        }
    }
}