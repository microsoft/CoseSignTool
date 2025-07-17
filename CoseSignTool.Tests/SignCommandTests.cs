// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Linq;
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
}
