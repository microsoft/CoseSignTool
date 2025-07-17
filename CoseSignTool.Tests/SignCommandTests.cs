// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Exceptions;
using CoseSign1.Certificates.Extensions;

namespace CoseSignTool.Tests;

[TestClass]
public class SignCommandTests
{
    // Certificates
    private static readonly X509Certificate2 SelfSignedCert = TestCertificateUtils.CreateCertificate(nameof(SignCommandTests) + " self signed");    // A self-signed cert
    private static readonly X509Certificate2Collection CertChain1 = TestCertificateUtils.CreateTestChain(nameof(SignCommandTests) + " set 1");      // A complete cert chain
    private static readonly X509Certificate2 Root1Priv = CertChain1[0];
    private static readonly X509Certificate2 Int1Priv = CertChain1[1];
    private static readonly X509Certificate2 Leaf1Priv = CertChain1[^1];

    // File paths to export them to
    private static readonly string PrivateKeyCertFileSelfSigned = Path.GetTempFileName() + "_SelfSigned.pfx";
    private static readonly string PublicKeyCertFileSelfSigned = Path.GetTempFileName() + "_SelfSigned.cer";
    private static readonly string PrivateKeyRootCertFile = Path.GetTempFileName() + ".pfx";
    private static readonly string PublicKeyIntermediateCertFile = Path.GetTempFileName() + ".cer";
    private static readonly string PublicKeyRootCertFile = Path.GetTempFileName() + ".cer";
    private static readonly string PrivateKeyCertFileChained = Path.GetTempFileName() + ".pfx";
    private static readonly string PrivateKeyCertFileChainedWithPassword = Path.GetTempFileName() + ".pfx";
    private static readonly string CertPassword = Guid.NewGuid().ToString();

    public SignCommandTests()
    {
        // export generated certs to files
        File.WriteAllBytes(PrivateKeyCertFileSelfSigned, SelfSignedCert.Export(X509ContentType.Pkcs12));
        File.WriteAllBytes(PublicKeyCertFileSelfSigned, SelfSignedCert.Export(X509ContentType.Cert));
        File.WriteAllBytes(PrivateKeyRootCertFile, Root1Priv.Export(X509ContentType.Pkcs12));
        File.WriteAllBytes(PublicKeyRootCertFile, Root1Priv.Export(X509ContentType.Cert));
        File.WriteAllBytes(PublicKeyIntermediateCertFile, Int1Priv.Export(X509ContentType.Cert));
        File.WriteAllBytes(PrivateKeyCertFileChained, Leaf1Priv.Export(X509ContentType.Pkcs12));
        File.WriteAllBytes(PrivateKeyCertFileChainedWithPassword, Leaf1Priv.Export(X509ContentType.Pkcs12, CertPassword));
    }

    [TestMethod]
    public void SignWithDefaultProtectedFlagInHeaderFile()
    {
        string headersFile = FileSystemUtils.GenerateHeadersFile(@"[{""label"":""created-at"",""value"":190}]");
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign
        string[] args = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileSelfSigned, @"/ih", headersFile, @"/ep"];
        var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
        badArg.Should().BeNull("badArg should be null.");

        var cmd1 = new SignCommand();
        cmd1.ApplyOptions(provider);

        cmd1.IntHeaders.ForEach(h => h.IsProtected.Should().Be(false, "Protected flag is not set to default value of false when unsupplied"));
    }

    [TestMethod]
    public void SignWithCommandLineAndInputHeaderFile()
    {
        string headersFile = FileSystemUtils.GenerateHeadersFile(@"[{""label"":""created-at"",""value"":190,""protected"":true},{""label"":""header2"",""value"":88897,""protected"":true}]");
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign
        // The unprotected header on the command line must be ignored
        string[] args = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileSelfSigned, @"/ih", headersFile, @"/ep", "iuh", "created-at=1234567"];
        var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
        badArg.Should().BeNull("badArg should be null.");

        var cmd1 = new SignCommand();
        cmd1.ApplyOptions(provider);

        cmd1.IntHeaders.Count.Should().Be(2, "When both input file and command line headers are supplied, the command line headers are not ignored");

        cmd1.IntHeaders.ForEach(h => h.IsProtected.Should().Be(true, "Protected flag is not set to default value of false when unsupplied"));
    }

    [TestMethod]
    public void SignWithPfxCertificateChain_ExtractsAllCertificatesFromPfx()
    {
        // Arrange - Create a PFX file containing the full certificate chain
        // Use the PFX-specific chain where only leaf has private key
        X509Certificate2Collection pfxChain = TestCertificateUtils.CreateTestChainForPfx(nameof(SignWithPfxCertificateChain_ExtractsAllCertificatesFromPfx));
        string pfxChainFile = Path.GetTempFileName() + "_Chain.pfx";
        try
        {
            // Export the entire chain to a single PFX file
            X509Certificate2Collection chainCollection = new();
            chainCollection.AddRange(pfxChain);
            
            byte[] pfxBytes = chainCollection.Export(X509ContentType.Pkcs12);
            File.WriteAllBytes(pfxChainFile, pfxBytes);

            string payloadFile = FileSystemUtils.GeneratePayloadFile();

            // Act - Sign using the PFX with full chain
            string[] args = ["sign", "/p", payloadFile, "/pfx", pfxChainFile, "/ep"];
            var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            var cmd = new SignCommand();
            cmd.ApplyOptions(provider);

            // Verify LoadCert extracts the signing certificate and additional roots
            var (cert, additionalRoots) = cmd.LoadCert();

            // Assert
            cert.Should().NotBeNull("Signing certificate should be found");
            cert.HasPrivateKey.Should().BeTrue("Signing certificate should have private key");
            
            additionalRoots.Should().NotBeNull("Additional roots should be extracted from PFX");
            additionalRoots!.Count.Should().BeGreaterThan(0, "Should have additional certificates from the chain");
            
            // Verify that only the leaf certificate has a private key
            var leafCert = pfxChain.Cast<X509Certificate2>().First(c => c.HasPrivateKey);
            cert.Thumbprint.Should().Be(leafCert.Thumbprint, "Should select the certificate with private key as signing cert");
            
            // Verify that the additional roots contain only public key certificates
            foreach (var additionalCert in additionalRoots)
            {
                additionalCert.HasPrivateKey.Should().BeFalse("Additional root certificates should not have private keys");
            }
            
            // Verify that the additional roots contain the other certificates from the chain
            // (excluding the signing certificate itself)
            var expectedAdditionalCerts = pfxChain.Cast<X509Certificate2>()
                .Where(c => !c.Equals(cert))
                .ToList();
            
            additionalRoots.Count.Should().Be(expectedAdditionalCerts.Count, 
                "Should extract all non-signing certificates as additional roots");

            // Verify the sign operation completes successfully
            ExitCode result = cmd.Run();
            result.Should().Be(ExitCode.Success, "Sign operation should succeed");
        }
        finally
        {
            // Cleanup
            if (File.Exists(pfxChainFile))
            {
                File.Delete(pfxChainFile);
            }
            
            // Dispose certificates
            foreach (var cert in pfxChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void SignWithPfxCertificateChain_UsesAdditionalRootsForChainBuilding()
    {
        // Arrange - Create a PFX file containing the full certificate chain
        // Use the PFX-specific chain where only leaf has private key
        X509Certificate2Collection pfxChain = TestCertificateUtils.CreateTestChainForPfx(nameof(SignWithPfxCertificateChain_UsesAdditionalRootsForChainBuilding));
        string pfxChainFile = Path.GetTempFileName() + "_ChainForValidation.pfx";
        try
        {
            // Export the entire chain to a single PFX file
            X509Certificate2Collection chainCollection = new();
            chainCollection.AddRange(pfxChain);
            
            byte[] pfxBytes = chainCollection.Export(X509ContentType.Pkcs12);
            File.WriteAllBytes(pfxChainFile, pfxBytes);

            string payloadFile = FileSystemUtils.GeneratePayloadFile();
            string signatureFile = Path.GetTempFileName() + ".cose";

            try
            {
                // Act - Sign using the PFX with full chain
                string[] args = ["sign", "/p", payloadFile, "/pfx", pfxChainFile, "/sf", signatureFile];
                var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
                badArg.Should().BeNull("badArg should be null.");

                var cmd = new SignCommand();
                cmd.ApplyOptions(provider);

                ExitCode result = cmd.Run();
                result.Should().Be(ExitCode.Success, "Sign operation should succeed with certificate chain");

                // Assert - Verify that the signature file was created and contains valid COSE signature
                File.Exists(signatureFile).Should().BeTrue("Signature file should be created");
                
                byte[] signatureBytes = File.ReadAllBytes(signatureFile);
                signatureBytes.Length.Should().BeGreaterThan(0, "Signature file should not be empty");
                
                // Verify we can read the COSE signature (basic validation)
                var coseMessage = CoseSign1Message.DecodeSign1(signatureBytes);
                coseMessage.Should().NotBeNull("Should be able to decode the COSE signature");

                // Extract and validate the certificate chain from the COSE message
                bool foundSigningCert = coseMessage.TryGetSigningCertificate(out X509Certificate2? extractedSigningCert);
                foundSigningCert.Should().BeTrue("Should be able to extract signing certificate from COSE message");
                extractedSigningCert.Should().NotBeNull("Extracted signing certificate should not be null");

                bool foundCertChain = coseMessage.TryGetCertificateChain(out List<X509Certificate2>? extractedCertChain);
                foundCertChain.Should().BeTrue("Should be able to extract certificate chain from COSE message");
                extractedCertChain.Should().NotBeNull("Extracted certificate chain should not be null");
                extractedCertChain!.Count.Should().Be(3, "Certificate chain should contain all 3 certificates (root, intermediate, leaf)");

                // Verify that the extracted signing certificate matches our test leaf certificate
                var expectedSigningCert = pfxChain.Cast<X509Certificate2>().First(c => c.HasPrivateKey);
                extractedSigningCert!.Thumbprint.Should().Be(expectedSigningCert.Thumbprint, 
                    "Extracted signing certificate should match the expected signing certificate");

                // Verify the certificate chain contains all expected certificates
                var expectedCertificates = pfxChain.Cast<X509Certificate2>().ToList();
                foreach (var expectedCert in expectedCertificates)
                {
                    extractedCertChain.Any(c => c.Thumbprint == expectedCert.Thumbprint).Should().BeTrue(
                        $"Certificate chain should contain certificate with subject '{expectedCert.Subject}'");
                }
                
                // Verify that intermediate and root certificates in the extracted chain don't have private keys
                // (This validates that the PFX structure was correctly built with only leaf having private key)
                var nonLeafCerts = extractedCertChain.Where(c => c.Thumbprint != expectedSigningCert.Thumbprint);
                foreach (var cert in nonLeafCerts)
                {
                    cert.HasPrivateKey.Should().BeFalse($"Non-leaf certificate with subject '{cert.Subject}' should not have private key");
                }
            }
            finally
            {
                if (File.Exists(signatureFile))
                {
                    File.Delete(signatureFile);
                }
            }
        }
        finally
        {
            // Cleanup
            if (File.Exists(pfxChainFile))
            {
                File.Delete(pfxChainFile);
            }
            
            // Dispose certificates
            foreach (var cert in pfxChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void SignWithFullPrivateKeyPfxCertificateChain_UsesAdditionalRootsForChainBuilding()
    {
        // Arrange - Create a PFX file containing the full certificate chain
        // Use the PFX-specific chain where only leaf has private key
        X509Certificate2Collection pfxChain = TestCertificateUtils.CreateTestChain(nameof(SignWithFullPrivateKeyPfxCertificateChain_UsesAdditionalRootsForChainBuilding), leafFirst: true);
        string pfxChainFile = Path.GetTempFileName() + "_ChainForValidation.pfx";
        try
        {
            // Export the entire chain to a single PFX file
            X509Certificate2Collection chainCollection = new();
            chainCollection.AddRange(pfxChain);
            
            byte[] pfxBytes = chainCollection.Export(X509ContentType.Pkcs12);
            File.WriteAllBytes(pfxChainFile, pfxBytes);

            string payloadFile = FileSystemUtils.GeneratePayloadFile();
            string signatureFile = Path.GetTempFileName() + ".cose";

            try
            {
                // Act - Sign using the PFX with full chain
                string[] args = ["sign", "/p", payloadFile, "/pfx", pfxChainFile, "/sf", signatureFile];
                var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
                badArg.Should().BeNull("badArg should be null.");

                var cmd = new SignCommand();
                cmd.ApplyOptions(provider);

                ExitCode result = cmd.Run();
                result.Should().Be(ExitCode.Success, "Sign operation should succeed with certificate chain");

                // Assert - Verify that the signature file was created and contains valid COSE signature
                File.Exists(signatureFile).Should().BeTrue("Signature file should be created");
                
                byte[] signatureBytes = File.ReadAllBytes(signatureFile);
                signatureBytes.Length.Should().BeGreaterThan(0, "Signature file should not be empty");
                
                // Verify we can read the COSE signature (basic validation)
                var coseMessage = CoseSign1Message.DecodeSign1(signatureBytes);
                coseMessage.Should().NotBeNull("Should be able to decode the COSE signature");

                // Extract and validate the certificate chain from the COSE message
                bool foundSigningCert = coseMessage.TryGetSigningCertificate(out X509Certificate2? extractedSigningCert);
                foundSigningCert.Should().BeTrue("Should be able to extract signing certificate from COSE message");
                extractedSigningCert.Should().NotBeNull("Extracted signing certificate should not be null");

                bool foundCertChain = coseMessage.TryGetCertificateChain(out List<X509Certificate2>? extractedCertChain);
                foundCertChain.Should().BeTrue("Should be able to extract certificate chain from COSE message");
                extractedCertChain.Should().NotBeNull("Extracted certificate chain should not be null");
                extractedCertChain!.Count.Should().Be(3, "Certificate chain should contain all 3 certificates (root, intermediate, leaf)");

                // Verify that the extracted signing certificate matches our test leaf certificate
                var expectedSigningCert = pfxChain.Cast<X509Certificate2>().First(c => c.HasPrivateKey);
                extractedSigningCert!.Thumbprint.Should().Be(expectedSigningCert.Thumbprint, 
                    "Extracted signing certificate should match the expected signing certificate");

                // Verify the certificate chain contains all expected certificates
                var expectedCertificates = pfxChain.Cast<X509Certificate2>().ToList();
                foreach (var expectedCert in expectedCertificates)
                {
                    extractedCertChain.Any(c => c.Thumbprint == expectedCert.Thumbprint).Should().BeTrue(
                        $"Certificate chain should contain certificate with subject '{expectedCert.Subject}'");
                }
                
                // Verify that intermediate and root certificates in the extracted chain have private keys as a test
                // (This validates that a PFX structure that was correctly built with the chain having private key)
                var nonLeafCerts = extractedCertChain.Where(c => c.Thumbprint != expectedSigningCert.Thumbprint);
                foreach (var cert in nonLeafCerts)
                {
                    cert.HasPrivateKey.Should().BeFalse($"Non-leaf certificate with subject '{cert.Subject}' should not have private key when extracted from COSE message.");
                }
            }
            finally
            {
                if (File.Exists(signatureFile))
                {
                    File.Delete(signatureFile);
                }
            }
        }
        finally
        {
            // Cleanup
            if (File.Exists(pfxChainFile))
            {
                File.Delete(pfxChainFile);
            }
            
            // Dispose certificates
            foreach (var cert in pfxChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void LoadCertFromPfxWithThumbprintFindsSpecificCertificate()
    {
        // Create a PFX file containing a full certificate chain with only leaf having private key
        X509Certificate2Collection pfxChain = TestCertificateUtils.CreateTestChainForPfx(nameof(LoadCertFromPfxWithThumbprintFindsSpecificCertificate));
        string pfxFileWithChain = Path.GetTempFileName() + "_chain.pfx";
        
        try
        {
            // Export the full certificate chain to a PFX file
            X509Certificate2Collection chainCollection = new();
            chainCollection.AddRange(pfxChain);
            byte[] pfxBytes = chainCollection.Export(X509ContentType.Pkcs12, CertPassword);
            File.WriteAllBytes(pfxFileWithChain, pfxBytes);

            // Get the leaf certificate (the one with private key)
            var leafCert = pfxChain.Cast<X509Certificate2>().First(c => c.HasPrivateKey);

            // Create a SignCommand and configure it to use the PFX with a specific thumbprint
            var cmd = new SignCommand
            {
                PfxCertificate = pfxFileWithChain,
                Password = CertPassword,
                Thumbprint = leafCert.Thumbprint // Specify the leaf certificate's thumbprint
            };

            // Test LoadCert method
            var (signingCert, additionalRoots) = cmd.LoadCert();
            
            // Verify the signing certificate matches the specified thumbprint
            signingCert.Should().NotBeNull("Signing certificate should be found");
            signingCert.Thumbprint.Should().Be(leafCert.Thumbprint, "Should find the certificate with the specified thumbprint");
            signingCert.HasPrivateKey.Should().BeTrue("Signing certificate should have private key");
            
            // Verify additional roots contain the other certificates and they don't have private keys
            additionalRoots.Should().NotBeNull("Additional roots should be extracted");
            additionalRoots.Should().HaveCount(2, "Should have root and intermediate certificates as additional roots");
            additionalRoots.Should().NotContain(signingCert, "Additional roots should not contain the signing certificate");
            
            // Verify that additional roots don't have private keys
            foreach (var additionalCert in additionalRoots!)
            {
                additionalCert.HasPrivateKey.Should().BeFalse("Additional root certificates should not have private keys");
            }
        }
        finally
        {
            if (File.Exists(pfxFileWithChain))
            {
                File.Delete(pfxFileWithChain);
            }
            
            // Dispose certificates
            foreach (var cert in pfxChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void LoadCertFromPfxWithInvalidThumbprintThrowsException()
    {
        // Create a PFX file containing a full certificate chain with only leaf having private key
        X509Certificate2Collection pfxChain = TestCertificateUtils.CreateTestChainForPfx(nameof(LoadCertFromPfxWithInvalidThumbprintThrowsException));
        string pfxFileWithChain = Path.GetTempFileName() + "_chain.pfx";
        
        try
        {
            // Export the full certificate chain to a PFX file
            X509Certificate2Collection chainCollection = new();
            chainCollection.AddRange(pfxChain);
            byte[] pfxBytes = chainCollection.Export(X509ContentType.Pkcs12, CertPassword);
            File.WriteAllBytes(pfxFileWithChain, pfxBytes);

            // Create a SignCommand with an invalid thumbprint
            var cmd = new SignCommand
            {
                PfxCertificate = pfxFileWithChain,
                Password = CertPassword,
                Thumbprint = "INVALIDTHUMBPRINT1234567890ABCDEF12345678" // Non-existent thumbprint
            };

            // Test LoadCert method should throw exception
            Action loadCertAction = () => cmd.LoadCert();
            loadCertAction.Should().Throw<CoseSign1CertificateException>()
                .WithMessage("*No certificate with private key and thumbprint 'INVALIDTHUMBPRINT1234567890ABCDEF12345678' found in PFX file*");
        }
        finally
        {
            if (File.Exists(pfxFileWithChain))
            {
                File.Delete(pfxFileWithChain);
            }
            
            // Dispose certificates
            foreach (var cert in pfxChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void SignWithPfxAndThumbprintSucceeds()
    {
        // Create a PFX file containing a full certificate chain with only leaf having private key
        X509Certificate2Collection pfxChain = TestCertificateUtils.CreateTestChainForPfx(nameof(SignWithPfxAndThumbprintSucceeds));
        string pfxFileWithChain = Path.GetTempFileName() + "_chain.pfx";
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        
        try
        {
            // Export the full certificate chain to a PFX file
            X509Certificate2Collection chainCollection = new();
            chainCollection.AddRange(pfxChain);
            byte[] pfxBytes = chainCollection.Export(X509ContentType.Pkcs12, CertPassword);
            File.WriteAllBytes(pfxFileWithChain, pfxBytes);

            // Get the leaf certificate (the one with private key)
            var leafCert = pfxChain.Cast<X509Certificate2>().First(c => c.HasPrivateKey);

            // Sign using the PFX with a specific thumbprint
            string[] args = ["sign", "/p", payloadFile, "/pfx", pfxFileWithChain, "/pw", CertPassword, "/th", leafCert.Thumbprint, "/ep"];
            var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            var cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Verify signing succeeded
            result.Should().Be(ExitCode.Success, "Signing with PFX and specific thumbprint should succeed");

            // Verify that the correct certificate was used
            var (signingCert, additionalRoots) = cmd.LoadCert();
            signingCert.Thumbprint.Should().Be(leafCert.Thumbprint, "Should use the certificate with the specified thumbprint");
            additionalRoots.Should().HaveCount(2, "Should extract other certificates as additional roots");
            
            // Verify that additional roots don't have private keys
            foreach (var additionalCert in additionalRoots!)
            {
                additionalCert.HasPrivateKey.Should().BeFalse("Additional root certificates should not have private keys");
            }

            // Verify that a signature file was created and extract certificates from it
            string? signatureFilePath = cmd.SignatureFile?.FullName;
            signatureFilePath.Should().NotBeNull("Signature file path should be set");
            File.Exists(signatureFilePath!).Should().BeTrue("Signature file should exist");

            byte[] signatureBytes = File.ReadAllBytes(signatureFilePath);
            var coseMessage = CoseSign1Message.DecodeSign1(signatureBytes);

            // Extract and validate certificates from the COSE message
            bool foundSigningCert = coseMessage.TryGetSigningCertificate(out X509Certificate2? extractedSigningCert);
            foundSigningCert.Should().BeTrue("Should extract signing certificate from COSE message");
            extractedSigningCert!.Thumbprint.Should().Be(leafCert.Thumbprint, 
                "Extracted signing certificate should match the specified thumbprint");

            bool foundCertChain = coseMessage.TryGetCertificateChain(out List<X509Certificate2>? extractedCertChain);
            foundCertChain.Should().BeTrue("Should extract certificate chain from COSE message");
            extractedCertChain.Should().NotBeNull("Certificate chain should not be null");
            extractedCertChain!.Count.Should().Be(3, "Should have full certificate chain embedded");

            // Verify that the chain contains the expected certificates
            var extractedLeafCert = extractedCertChain.FirstOrDefault(c => c.Thumbprint == leafCert.Thumbprint);
            extractedLeafCert.Should().NotBeNull("Leaf certificate should be in the chain");

            // Verify that other certificates from our PFX chain are also present
            var expectedCertificates = pfxChain.Cast<X509Certificate2>().ToList();
            foreach (var expectedCert in expectedCertificates)
            {
                extractedCertChain.Any(c => c.Thumbprint == expectedCert.Thumbprint).Should().BeTrue(
                    $"Certificate with subject '{expectedCert.Subject}' should be in the extracted chain");
            }

            // Clean up the signature file
            if (File.Exists(signatureFilePath))
            {
                File.Delete(signatureFilePath);
            }
        }
        finally
        {
            if (File.Exists(pfxFileWithChain))
            {
                File.Delete(pfxFileWithChain);
            }
            if (File.Exists(payloadFile))
            {
                File.Delete(payloadFile);
            }
            
            // Dispose certificates
            foreach (var cert in pfxChain)
            {
                cert.Dispose();
            }
        }
    }

    #region IsIssuer and Certificate Chain Building Tests

    [TestMethod]
    public void IsIssuer_ValidIssuerSubjectRelationship_ReturnsTrue()
    {
        // Arrange
        var certChain = TestCertificateUtils.CreateTestChain("IsIssuer Test Chain");
        var rootCert = certChain[0];
        var intermediateCert = certChain[1];
        var leafCert = certChain[2];

        try
        {
            // Act & Assert - Test root -> intermediate relationship
            bool rootIsIssuerOfIntermediate = (bool)typeof(SignCommand)
                .GetMethod("IsIssuer", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [rootCert, intermediateCert])!;

            rootIsIssuerOfIntermediate.Should().BeTrue("Root certificate should be issuer of intermediate certificate");

            // Act & Assert - Test intermediate -> leaf relationship
            bool intermediateIsIssuerOfLeaf = (bool)typeof(SignCommand)
                .GetMethod("IsIssuer", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [intermediateCert, leafCert])!;

            intermediateIsIssuerOfLeaf.Should().BeTrue("Intermediate certificate should be issuer of leaf certificate");

            // Act & Assert - Test invalid relationship (leaf should not be issuer of root)
            bool leafIsIssuerOfRoot = (bool)typeof(SignCommand)
                .GetMethod("IsIssuer", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [leafCert, rootCert])!;

            leafIsIssuerOfRoot.Should().BeFalse("Leaf certificate should not be issuer of root certificate");
        }
        finally
        {
            foreach (var cert in certChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void IsIssuer_SelfSignedCertificate_ReturnsTrue()
    {
        // Arrange
        var selfSignedCert = TestCertificateUtils.CreateCertificate("Self-Signed Test Certificate");

        try
        {
            // Act
            bool result = (bool)typeof(SignCommand)
                .GetMethod("IsIssuer", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [selfSignedCert, selfSignedCert])!;

            // Assert
            result.Should().BeTrue("Self-signed certificate should be its own issuer");
        }
        finally
        {
            selfSignedCert.Dispose();
        }
    }

    [TestMethod]
    public void IsIssuer_UnrelatedCertificates_ReturnsFalse()
    {
        // Arrange
        var cert1 = TestCertificateUtils.CreateCertificate("Unrelated Certificate 1");
        var cert2 = TestCertificateUtils.CreateCertificate("Unrelated Certificate 2");

        try
        {
            // Act
            bool result = (bool)typeof(SignCommand)
                .GetMethod("IsIssuer", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [cert1, cert2])!;

            // Assert
            result.Should().BeFalse("Unrelated certificates should not have issuer relationship");
        }
        finally
        {
            cert1.Dispose();
            cert2.Dispose();
        }
    }

    [TestMethod]
    public void IsIssuer_DifferentSubjectIssuerNames_ReturnsFalse()
    {
        // Arrange
        var certChain1 = TestCertificateUtils.CreateTestChain("Chain 1");
        var certChain2 = TestCertificateUtils.CreateTestChain("Chain 2");

        try
        {
            // Act - Try to use certificate from chain 1 as issuer of certificate from chain 2
            bool result = (bool)typeof(SignCommand)
                .GetMethod("IsIssuer", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [certChain1[0], certChain2[1]])!;

            // Assert
            result.Should().BeFalse("Certificates from different chains should not have issuer relationship");
        }
        finally
        {
            foreach (var cert in certChain1)
            {
                cert.Dispose();
            }
            foreach (var cert in certChain2)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void BuildCertificateChain_ValidChain_ReturnsCorrectOrder()
    {
        // Arrange
        var originalChain = TestCertificateUtils.CreateTestChain("Chain Building Test");
        var shuffledCollection = new X509Certificate2Collection();
        
        // Add certificates in random order to test sorting
        shuffledCollection.Add(originalChain[2]); // leaf
        shuffledCollection.Add(originalChain[0]); // root
        shuffledCollection.Add(originalChain[1]); // intermediate

        try
        {
            // Act
            var result = (List<X509Certificate2>)typeof(SignCommand)
                .GetMethod("BuildCertificateChain", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [shuffledCollection, null])!;

            // Assert
            result.Should().NotBeNull("Built chain should not be null");
            result.Count.Should().Be(3, "Built chain should contain all certificates");
            
            // First certificate should be the leaf (the one that's not an issuer of others)
            result[0].Subject.Should().Be(originalChain[2].Subject, "First certificate should be the leaf");
            
            // Verify the chain order: leaf -> intermediate -> root
            bool leafToIntermediateRelation = (bool)typeof(SignCommand)
                .GetMethod("IsIssuer", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [result[1], result[0]])!;
            leafToIntermediateRelation.Should().BeTrue("Second certificate should be issuer of first (leaf)");

            bool intermediateToRootRelation = (bool)typeof(SignCommand)
                .GetMethod("IsIssuer", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [result[2], result[1]])!;
            intermediateToRootRelation.Should().BeTrue("Third certificate should be issuer of second (intermediate)");
        }
        finally
        {
            foreach (var cert in originalChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void BuildCertificateChain_WithSpecificThumbprint_ReturnsChainStartingWithSpecifiedCert()
    {
        // Arrange
        var originalChain = TestCertificateUtils.CreateTestChain("Thumbprint Chain Test");
        var collection = new X509Certificate2Collection();
        foreach (var cert in originalChain)
        {
            collection.Add(cert);
        }

        // Use the intermediate certificate's thumbprint
        string targetThumbprint = originalChain[1].Thumbprint;

        try
        {
            // Act
            var result = (List<X509Certificate2>)typeof(SignCommand)
                .GetMethod("BuildCertificateChain", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [collection, targetThumbprint])!;

            // Assert
            result.Should().NotBeNull("Built chain should not be null");
            result.Count.Should().BeGreaterThan(0, "Built chain should contain certificates");
            result[0].Thumbprint.Should().Be(targetThumbprint, "First certificate should match the specified thumbprint");
        }
        finally
        {
            foreach (var cert in originalChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void BuildCertificateChain_WithInvalidThumbprint_ReturnsEmptyList()
    {
        // Arrange
        var originalChain = TestCertificateUtils.CreateTestChain("Invalid Thumbprint Test");
        var collection = new X509Certificate2Collection();
        foreach (var cert in originalChain)
        {
            collection.Add(cert);
        }

        string invalidThumbprint = "INVALIDTHUMBPRINT1234567890";

        try
        {
            // Act
            var result = (List<X509Certificate2>)typeof(SignCommand)
                .GetMethod("BuildCertificateChain", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [collection, invalidThumbprint])!;

            // Assert
            result.Should().NotBeNull("Result should not be null");
            result.Count.Should().Be(0, "Should return empty list for invalid thumbprint");
        }
        finally
        {
            foreach (var cert in originalChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void BuildCertificateChain_SingleSelfSignedCertificate_ReturnsSingleCertificate()
    {
        // Arrange
        var selfSignedCert = TestCertificateUtils.CreateCertificate("Single Self-Signed Test");
        var collection = new X509Certificate2Collection { selfSignedCert };

        try
        {
            // Act
            var result = (List<X509Certificate2>)typeof(SignCommand)
                .GetMethod("BuildCertificateChain", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [collection, null])!;

            // Assert
            result.Should().NotBeNull("Built chain should not be null");
            result.Count.Should().Be(1, "Should return single certificate");
            result[0].Thumbprint.Should().Be(selfSignedCert.Thumbprint, "Should return the self-signed certificate");
        }
        finally
        {
            selfSignedCert.Dispose();
        }
    }

    [TestMethod]
    public void IsIssuerOfAnyCertificate_CertificateIsIssuer_ReturnsTrue()
    {
        // Arrange
        var certChain = TestCertificateUtils.CreateTestChain("IsIssuerOfAny Test");
        var rootCert = certChain[0];
        var certList = certChain.Cast<X509Certificate2>().ToList();

        try
        {
            // Act
            bool result = (bool)typeof(SignCommand)
                .GetMethod("IsIssuerOfAnyCertificate", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [rootCert, certList])!;

            // Assert
            result.Should().BeTrue("Root certificate should be issuer of other certificates in the chain");
        }
        finally
        {
            foreach (var cert in certChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void IsIssuerOfAnyCertificate_CertificateIsNotIssuer_ReturnsFalse()
    {
        // Arrange
        var certChain = TestCertificateUtils.CreateTestChain("IsIssuerOfAny Leaf Test");
        var leafCert = certChain[2]; // Leaf certificate
        var certList = certChain.Cast<X509Certificate2>().ToList();

        try
        {
            // Act
            bool result = (bool)typeof(SignCommand)
                .GetMethod("IsIssuerOfAnyCertificate", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [leafCert, certList])!;

            // Assert
            result.Should().BeFalse("Leaf certificate should not be issuer of any other certificates");
        }
        finally
        {
            foreach (var cert in certChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void FindIssuer_ValidIssuerExists_ReturnsCorrectIssuer()
    {
        // Arrange
        var certChain = TestCertificateUtils.CreateTestChain("FindIssuer Test");
        var leafCert = certChain[2];
        var candidates = certChain.Cast<X509Certificate2>().ToList();

        try
        {
            // Act
            var result = (X509Certificate2?)typeof(SignCommand)
                .GetMethod("FindIssuer", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [leafCert, candidates])!;

            // Assert
            result.Should().NotBeNull("Should find an issuer for the leaf certificate");
            result!.Subject.Should().Be(certChain[1].Subject, "Should find the intermediate certificate as issuer");
        }
        finally
        {
            foreach (var cert in certChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void FindIssuer_NoValidIssuerExists_ReturnsNull()
    {
        // Arrange
        var cert1 = TestCertificateUtils.CreateCertificate("Standalone Certificate 1");
        var cert2 = TestCertificateUtils.CreateCertificate("Standalone Certificate 2");
        var candidates = new List<X509Certificate2> { cert2 };

        try
        {
            // Act
            var result = (X509Certificate2?)typeof(SignCommand)
                .GetMethod("FindIssuer", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [cert1, candidates])!;

            // Assert
            result.Should().BeNull("Should not find issuer for unrelated certificate");
        }
        finally
        {
            cert1.Dispose();
            cert2.Dispose();
        }
    }

    #endregion
}
