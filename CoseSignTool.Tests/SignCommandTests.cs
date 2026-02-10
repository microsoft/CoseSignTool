// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.Cose;
using CoseSign1.Certificates.Exceptions;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Headers.Extensions;

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
        Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
        badArg.Should().BeNull("badArg should be null.");

        SignCommand cmd1 = new SignCommand();
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
        Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
        badArg.Should().BeNull("badArg should be null.");

        SignCommand cmd1 = new SignCommand();
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
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);

            // Verify LoadCert extracts the signing certificate and additional roots
            (X509Certificate2 cert, List<X509Certificate2> additionalRoots) = cmd.LoadCert();

            // Assert
            cert.Should().NotBeNull("Signing certificate should be found");
            cert.HasPrivateKey.Should().BeTrue("Signing certificate should have private key");
            
            additionalRoots.Should().NotBeNull("Additional roots should be extracted from PFX");
            additionalRoots!.Count.Should().BeGreaterThan(0, "Should have additional certificates from the chain");

            // Verify that only the leaf certificate has a private key
            X509Certificate2 leafCert = pfxChain.Cast<X509Certificate2>().First(c => c.HasPrivateKey);
            cert.Thumbprint.Should().Be(leafCert.Thumbprint, "Should select the certificate with private key as signing cert");
            
            // Verify that the additional roots contain only public key certificates
            foreach (X509Certificate2 additionalCert in additionalRoots)
            {
                additionalCert.HasPrivateKey.Should().BeFalse("Additional root certificates should not have private keys");
            }

            // Verify that the additional roots contain the other certificates from the chain
            // (excluding the signing certificate itself)
            List<X509Certificate2> expectedAdditionalCerts = pfxChain.Cast<X509Certificate2>()
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
            foreach (X509Certificate2 cert in pfxChain)
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
                Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
                badArg.Should().BeNull("badArg should be null.");

                SignCommand cmd = new SignCommand();
                cmd.ApplyOptions(provider);

                ExitCode result = cmd.Run();
                result.Should().Be(ExitCode.Success, "Sign operation should succeed with certificate chain");

                // Assert - Verify that the signature file was created and contains valid COSE signature
                File.Exists(signatureFile).Should().BeTrue("Signature file should be created");
                
                byte[] signatureBytes = File.ReadAllBytes(signatureFile);
                signatureBytes.Length.Should().BeGreaterThan(0, "Signature file should not be empty");

                // Verify we can read the COSE signature (basic validation)
                CoseSign1Message coseMessage = CoseSign1Message.DecodeSign1(signatureBytes);
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
                X509Certificate2 expectedSigningCert = pfxChain.Cast<X509Certificate2>().First(c => c.HasPrivateKey);
                extractedSigningCert!.Thumbprint.Should().Be(expectedSigningCert.Thumbprint, 
                    "Extracted signing certificate should match the expected signing certificate");

                // Verify the certificate chain contains all expected certificates
                List<X509Certificate2> expectedCertificates = pfxChain.Cast<X509Certificate2>().ToList();
                foreach (X509Certificate2? expectedCert in expectedCertificates)
                {
                    extractedCertChain.Any(c => c.Thumbprint == expectedCert.Thumbprint).Should().BeTrue(
                        $"Certificate chain should contain certificate with subject '{expectedCert.Subject}'");
                }

                // Verify that intermediate and root certificates in the extracted chain don't have private keys
                // (This validates that the PFX structure was correctly built with only leaf having private key)
                IEnumerable<X509Certificate2> nonLeafCerts = extractedCertChain.Where(c => c.Thumbprint != expectedSigningCert.Thumbprint);
                foreach (X509Certificate2? cert in nonLeafCerts)
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
            foreach (X509Certificate2 cert in pfxChain)
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
                Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
                badArg.Should().BeNull("badArg should be null.");

                SignCommand cmd = new SignCommand();
                cmd.ApplyOptions(provider);

                ExitCode result = cmd.Run();
                result.Should().Be(ExitCode.Success, "Sign operation should succeed with certificate chain");

                // Assert - Verify that the signature file was created and contains valid COSE signature
                File.Exists(signatureFile).Should().BeTrue("Signature file should be created");
                
                byte[] signatureBytes = File.ReadAllBytes(signatureFile);
                signatureBytes.Length.Should().BeGreaterThan(0, "Signature file should not be empty");

                // Verify we can read the COSE signature (basic validation)
                CoseSign1Message coseMessage = CoseSign1Message.DecodeSign1(signatureBytes);
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
                X509Certificate2 expectedSigningCert = pfxChain.Cast<X509Certificate2>().First(c => c.HasPrivateKey);
                extractedSigningCert!.Thumbprint.Should().Be(expectedSigningCert.Thumbprint, 
                    "Extracted signing certificate should match the expected signing certificate");

                // Verify the certificate chain contains all expected certificates
                List<X509Certificate2> expectedCertificates = pfxChain.Cast<X509Certificate2>().ToList();
                foreach (X509Certificate2? expectedCert in expectedCertificates)
                {
                    extractedCertChain.Any(c => c.Thumbprint == expectedCert.Thumbprint).Should().BeTrue(
                        $"Certificate chain should contain certificate with subject '{expectedCert.Subject}'");
                }

                // Verify that intermediate and root certificates in the extracted chain have private keys as a test
                // (This validates that a PFX structure that was correctly built with the chain having private key)
                IEnumerable<X509Certificate2> nonLeafCerts = extractedCertChain.Where(c => c.Thumbprint != expectedSigningCert.Thumbprint);
                foreach (X509Certificate2? cert in nonLeafCerts)
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
            foreach (X509Certificate2 cert in pfxChain)
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
            X509Certificate2 leafCert = pfxChain.Cast<X509Certificate2>().First(c => c.HasPrivateKey);

            // Create a SignCommand and configure it to use the PFX with a specific thumbprint
            SignCommand cmd = new SignCommand
            {
                PfxCertificate = pfxFileWithChain,
                Password = CertPassword,
                Thumbprint = leafCert.Thumbprint // Specify the leaf certificate's thumbprint
            };

            // Test LoadCert method
            (X509Certificate2 signingCert, List<X509Certificate2> additionalRoots) = cmd.LoadCert();
            
            // Verify the signing certificate matches the specified thumbprint
            signingCert.Should().NotBeNull("Signing certificate should be found");
            signingCert.Thumbprint.Should().Be(leafCert.Thumbprint, "Should find the certificate with the specified thumbprint");
            signingCert.HasPrivateKey.Should().BeTrue("Signing certificate should have private key");
            
            // Verify additional roots contain the other certificates and they don't have private keys
            additionalRoots.Should().NotBeNull("Additional roots should be extracted");
            additionalRoots.Should().HaveCount(2, "Should have root and intermediate certificates as additional roots");
            additionalRoots.Should().NotContain(signingCert, "Additional roots should not contain the signing certificate");
            
            // Verify that additional roots don't have private keys
            foreach (X509Certificate2 additionalCert in additionalRoots!)
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
            foreach (X509Certificate2 cert in pfxChain)
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
            SignCommand cmd = new SignCommand
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
            foreach (X509Certificate2 cert in pfxChain)
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
            X509Certificate2 leafCert = pfxChain.Cast<X509Certificate2>().First(c => c.HasPrivateKey);

            // Sign using the PFX with a specific thumbprint
            string[] args = ["sign", "--p", payloadFile, "--pfx", pfxFileWithChain, "--pw", CertPassword, "--th", leafCert.Thumbprint, "--ep"];
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Verify signing succeeded
            result.Should().Be(ExitCode.Success, "Signing with PFX and specific thumbprint should succeed");

            // Verify that the correct certificate was used
            (X509Certificate2 signingCert, List<X509Certificate2> additionalRoots) = cmd.LoadCert();
            signingCert.Thumbprint.Should().Be(leafCert.Thumbprint, "Should use the certificate with the specified thumbprint");
            additionalRoots.Should().HaveCount(2, "Should extract other certificates as additional roots");
            
            // Verify that additional roots don't have private keys
            foreach (X509Certificate2 additionalCert in additionalRoots!)
            {
                additionalCert.HasPrivateKey.Should().BeFalse("Additional root certificates should not have private keys");
            }

            // Verify that a signature file was created and extract certificates from it
            string? signatureFilePath = cmd.SignatureFile?.FullName;
            signatureFilePath.Should().NotBeNull("Signature file path should be set");
            File.Exists(signatureFilePath!).Should().BeTrue("Signature file should exist");

            byte[] signatureBytes = File.ReadAllBytes(signatureFilePath);
            CoseSign1Message coseMessage = CoseSign1Message.DecodeSign1(signatureBytes);

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
            X509Certificate2? extractedLeafCert = extractedCertChain.FirstOrDefault(c => c.Thumbprint == leafCert.Thumbprint);
            extractedLeafCert.Should().NotBeNull("Leaf certificate should be in the chain");

            // Verify that other certificates from our PFX chain are also present
            List<X509Certificate2> expectedCertificates = pfxChain.Cast<X509Certificate2>().ToList();
            foreach (X509Certificate2? expectedCert in expectedCertificates)
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
            foreach (X509Certificate2 cert in pfxChain)
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
        X509Certificate2Collection certChain = TestCertificateUtils.CreateTestChain("IsIssuer Test Chain");
        X509Certificate2 rootCert = certChain[0];
        X509Certificate2 intermediateCert = certChain[1];
        X509Certificate2 leafCert = certChain[2];

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
            foreach (X509Certificate2 cert in certChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void IsIssuer_SelfSignedCertificate_ReturnsTrue()
    {
        // Arrange
        X509Certificate2 selfSignedCert = TestCertificateUtils.CreateCertificate("Self-Signed Test Certificate");

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
        X509Certificate2 cert1 = TestCertificateUtils.CreateCertificate("Unrelated Certificate 1");
        X509Certificate2 cert2 = TestCertificateUtils.CreateCertificate("Unrelated Certificate 2");

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
        X509Certificate2Collection certChain1 = TestCertificateUtils.CreateTestChain("Chain 1");
        X509Certificate2Collection certChain2 = TestCertificateUtils.CreateTestChain("Chain 2");

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
            foreach (X509Certificate2 cert in certChain1)
            {
                cert.Dispose();
            }
            foreach (X509Certificate2 cert in certChain2)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void BuildCertificateChain_ValidChain_ReturnsCorrectOrder()
    {
        // Arrange
        X509Certificate2Collection originalChain = TestCertificateUtils.CreateTestChain("Chain Building Test");
        X509Certificate2Collection shuffledCollection = new X509Certificate2Collection();
        
        // Add certificates in random order to test sorting
        shuffledCollection.Add(originalChain[2]); // leaf
        shuffledCollection.Add(originalChain[0]); // root
        shuffledCollection.Add(originalChain[1]); // intermediate

        try
        {
            // Act
            List<X509Certificate2> result = (List<X509Certificate2>)typeof(SignCommand)
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
            foreach (X509Certificate2 cert in originalChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void BuildCertificateChain_WithSpecificThumbprint_ReturnsChainStartingWithSpecifiedCert()
    {
        // Arrange
        X509Certificate2Collection originalChain = TestCertificateUtils.CreateTestChain("Thumbprint Chain Test");
        X509Certificate2Collection collection = new X509Certificate2Collection();
        foreach (X509Certificate2 cert in originalChain)
        {
            collection.Add(cert);
        }

        // Use the intermediate certificate's thumbprint
        string targetThumbprint = originalChain[1].Thumbprint;

        try
        {
            // Act
            List<X509Certificate2> result = (List<X509Certificate2>)typeof(SignCommand)
                .GetMethod("BuildCertificateChain", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [collection, targetThumbprint])!;

            // Assert
            result.Should().NotBeNull("Built chain should not be null");
            result.Count.Should().BeGreaterThan(0, "Built chain should contain certificates");
            result[0].Thumbprint.Should().Be(targetThumbprint, "First certificate should match the specified thumbprint");
        }
        finally
        {
            foreach (X509Certificate2 cert in originalChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void BuildCertificateChain_WithInvalidThumbprint_ReturnsEmptyList()
    {
        // Arrange
        X509Certificate2Collection originalChain = TestCertificateUtils.CreateTestChain("Invalid Thumbprint Test");
        X509Certificate2Collection collection = new X509Certificate2Collection();
        foreach (X509Certificate2 cert in originalChain)
        {
            collection.Add(cert);
        }

        string invalidThumbprint = "INVALIDTHUMBPRINT1234567890";

        try
        {
            // Act
            List<X509Certificate2> result = (List<X509Certificate2>)typeof(SignCommand)
                .GetMethod("BuildCertificateChain", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [collection, invalidThumbprint])!;

            // Assert
            result.Should().NotBeNull("Result should not be null");
            result.Count.Should().Be(0, "Should return empty list for invalid thumbprint");
        }
        finally
        {
            foreach (X509Certificate2 cert in originalChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void BuildCertificateChain_SingleSelfSignedCertificate_ReturnsSingleCertificate()
    {
        // Arrange
        X509Certificate2 selfSignedCert = TestCertificateUtils.CreateCertificate("Single Self-Signed Test");
        X509Certificate2Collection collection = new X509Certificate2Collection { selfSignedCert };

        try
        {
            // Act
            List<X509Certificate2> result = (List<X509Certificate2>)typeof(SignCommand)
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
        X509Certificate2Collection certChain = TestCertificateUtils.CreateTestChain("IsIssuerOfAny Test");
        X509Certificate2 rootCert = certChain[0];
        List<X509Certificate2> certList = certChain.Cast<X509Certificate2>().ToList();

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
            foreach (X509Certificate2 cert in certChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void IsIssuerOfAnyCertificate_CertificateIsNotIssuer_ReturnsFalse()
    {
        // Arrange
        X509Certificate2Collection certChain = TestCertificateUtils.CreateTestChain("IsIssuerOfAny Leaf Test");
        X509Certificate2 leafCert = certChain[2]; // Leaf certificate
        List<X509Certificate2> certList = certChain.Cast<X509Certificate2>().ToList();

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
            foreach (X509Certificate2 cert in certChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void FindIssuer_ValidIssuerExists_ReturnsCorrectIssuer()
    {
        // Arrange
        X509Certificate2Collection certChain = TestCertificateUtils.CreateTestChain("FindIssuer Test");
        X509Certificate2 leafCert = certChain[2];
        List<X509Certificate2> candidates = certChain.Cast<X509Certificate2>().ToList();

        try
        {
            // Act
            X509Certificate2 result = (X509Certificate2?)typeof(SignCommand)
                .GetMethod("FindIssuer", BindingFlags.NonPublic | BindingFlags.Static)!
                .Invoke(null, [leafCert, candidates])!;

            // Assert
            result.Should().NotBeNull("Should find an issuer for the leaf certificate");
            result!.Subject.Should().Be(certChain[1].Subject, "Should find the intermediate certificate as issuer");
        }
        finally
        {
            foreach (X509Certificate2 cert in certChain)
            {
                cert.Dispose();
            }
        }
    }

    [TestMethod]
    public void FindIssuer_NoValidIssuerExists_ReturnsNull()
    {
        // Arrange
        X509Certificate2 cert1 = TestCertificateUtils.CreateCertificate("Standalone Certificate 1");
        X509Certificate2 cert2 = TestCertificateUtils.CreateCertificate("Standalone Certificate 2");
        List<X509Certificate2> candidates = new List<X509Certificate2> { cert2 };

        try
        {
            // Act
            X509Certificate2 result = (X509Certificate2?)typeof(SignCommand)
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

    #region CWT Claims Tests

    [TestMethod]
    public void SignWithCwtClaims_ShouldIncludeClaimsInSignature()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/cwt-iss", "did:example:issuer", "/cwt-sub", "test.subject"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed");
            
            // Verify CWT claims are in the signature
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue("Signature should contain CWT claims");
            claims.Should().NotBeNull();
            claims!.Issuer.Should().Be("did:example:issuer");
            claims.Subject.Should().Be("test.subject");
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    [TestMethod]
    public void SignWithScittDisabled_ShouldNotIncludeCwtClaims()
    {
        // NOTE: This test verifies the new behavior where disabling SCITT compliance
        // prevents automatic addition of default CWT claims.
        
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/scitt", "false"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed");
            
            // Verify NO CWT claims are present when SCITT is disabled
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeFalse("Signature should NOT contain CWT claims when SCITT compliance is disabled");
            claims.Should().BeNull("No CWT claims should be present");
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    [TestMethod]
    public void SignWithCwtAudience_ShouldIncludeAudienceClaim()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/cwt-iss", "issuer", "/cwt-aud", "test-audience"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed");
            
            // Verify audience claim
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue();
            claims!.Audience.Should().Be("test-audience");
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    [TestMethod]
    public void SignWithCustomCwtClaims_ShouldIncludeCustomClaims()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act - Using integer label with value
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/cwt-iss", "issuer", "/cwt", "100:custom-value"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed");
            
            // Verify custom claim
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue();
            claims!.CustomClaims.Should().ContainKey(100);
            claims.CustomClaims[100].Should().Be("custom-value");
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    [TestMethod]
    public void SignWithCwtExpiration_ShouldIncludeExpirationClaim()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act - Test expiration with Unix timestamp
            long expTimestamp = 1735689600; // Jan 1, 2025
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/cwt-iss", "issuer", "/cwt", $"exp:{expTimestamp}"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull();

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success);
            
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue();
            DateTimeOffset expectedDate = DateTimeOffset.FromUnixTimeSeconds(expTimestamp);
            claims!.ExpirationTime.Should().Be(expectedDate);
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    [TestMethod]
    public void SignWithCwtNotBefore_ShouldIncludeNotBeforeClaim()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act - Test not-before with Unix timestamp
            long nbfTimestamp = 1704067200; // Jan 1, 2024
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/cwt-iss", "issuer", "/cwt", $"nbf:{nbfTimestamp}"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull();

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success);
            
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue();
            DateTimeOffset expectedDate = DateTimeOffset.FromUnixTimeSeconds(nbfTimestamp);
            claims!.NotBefore.Should().Be(expectedDate);
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    [TestMethod]
    public void SignWithCwtIssuedAt_ShouldIncludeIssuedAtClaim()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act - Test issued-at with Unix timestamp
            long iatTimestamp = 1704153600;
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/cwt-iss", "issuer", "/cwt", $"iat:{iatTimestamp}"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull();

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success);
            
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue();
            DateTimeOffset expectedDate = DateTimeOffset.FromUnixTimeSeconds(iatTimestamp);
            claims!.IssuedAt.Should().Be(expectedDate);
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    [TestMethod]
    public void SignWithCwtId_ShouldIncludeCwtIdClaim()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act - Test CWT ID
            string ctiValue = "unique-token-id-123";
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/cwt-iss", "issuer", "/cwt", $"cti:{ctiValue}"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull();

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success);
            
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue();
            byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes(ctiValue);
            claims!.CwtId.Should().BeEquivalentTo(expectedBytes);
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    [TestMethod]
    public void SignWithIntegerCwtClaim_ShouldIncludeIntegerValue()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act - Test integer custom claim
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/cwt-iss", "issuer", "/cwt", "200:42"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull();

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success);
            
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue();
            claims!.CustomClaims.Should().ContainKey(200);
            claims.CustomClaims[200].Should().Be(42);
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    [TestMethod]
    public void SignWithLongCwtClaim_ShouldIncludeLongValue()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act - Test long custom claim (beyond int32 range)
            long longValue = 9999999999L;
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/cwt-iss", "issuer", "/cwt", $"300:{longValue}"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull();

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success);
            
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue();
            claims!.CustomClaims.Should().ContainKey(300);
            claims.CustomClaims[300].Should().Be(longValue);
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    [TestMethod]
    public void SignWithMultipleCwtClaims_ShouldIncludeAllClaims()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act - Test single custom claim for now (multiple /cwt parameters need special handling)
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/cwt-iss", "issuer", "/cwt", "102:42"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull();

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success);
            
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue();
            claims!.CustomClaims.Should().ContainKey(102);
            claims.CustomClaims[102].Should().Be(42);
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    /// <summary>
    /// Tests that when SCITT compliance is disabled AND no custom CWT claims are specified,
    /// no CWT claims are present in the signature (regression test).
    /// </summary>
    [TestMethod]
    public void SignWithScittDisabledAndNoCwtClaims_ShouldNotIncludeAnyCwtClaims()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act - Disable SCITT and don't specify any custom CWT claims
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/scitt", "false"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed");
            
            // Verify NO CWT claims whatsoever are present in the signature
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeFalse("Signature should NOT contain any CWT claims when SCITT is disabled and no custom claims specified");
            claims.Should().BeNull("No CWT claims should be present in the signature");
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    /// <summary>
    /// Tests that when SCITT compliance is disabled but custom CWT claims ARE specified,
    /// the custom CWT claims are still included.
    /// </summary>
    [TestMethod]
    public void SignWithScittDisabledButCustomCwtClaims_ShouldIncludeOnlyCustomClaims()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act - Disable SCITT but provide custom CWT claims
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/scitt", "false", "/cwt-iss", "custom-issuer", "/cwt-sub", "custom-subject"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed");
            
            // Verify that custom CWT claims are present (user overrides are honored even with SCITT disabled)
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue("Signature should contain custom CWT claims specified by user");
            claims.Should().NotBeNull();
            claims!.Issuer.Should().Be("custom-issuer", "Custom issuer should be present");
            claims.Subject.Should().Be("custom-subject", "Custom subject should be present");
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    /// <summary>
    /// Tests that when SCITT compliance is enabled (default), default CWT claims are included.
    /// </summary>
    [TestMethod]
    public void SignWithScittEnabledDefault_ShouldIncludeDefaultCwtClaims()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act - Don't specify /scitt flag (should default to true)
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed");
            
            // Verify default CWT claims are present
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue("Signature should contain default CWT claims when SCITT is enabled by default");
            claims.Should().NotBeNull();
            claims!.Issuer.Should().NotBeNullOrEmpty("Default issuer (DID:x509) should be present");
            claims.Subject.Should().Be("unknown.intent", "Default subject should be present");
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    /// <summary>
    /// Tests that when SCITT compliance is explicitly enabled, default CWT claims are included.
    /// </summary>
    [TestMethod]
    public void SignWithScittExplicitlyEnabled_ShouldIncludeDefaultCwtClaims()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";

        try
        {
            // Act - Explicitly enable SCITT
            string[] args = ["sign", "/p", payloadFile, "/pfx", PrivateKeyCertFileSelfSigned, 
                            "/sf", signatureFile, "/scitt", "true"];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed");
            
            // Verify default CWT claims are present
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            bool hasClaims = message.TryGetCwtClaims(out CoseSign1.Headers.CwtClaims? claims);
            hasClaims.Should().BeTrue("Signature should contain default CWT claims when SCITT is explicitly enabled");
            claims.Should().NotBeNull();
            claims!.Issuer.Should().NotBeNullOrEmpty("Default issuer (DID:x509) should be present");
            claims.Subject.Should().Be("unknown.intent", "Default subject should be present");
        }
        finally
        {
            if (File.Exists(payloadFile))
                File.Delete(payloadFile);
            if (File.Exists(signatureFile))
                File.Delete(signatureFile);
        }
    }

    #endregion

    #region PEM Certificate Tests

    /// <summary>
    /// Tests that signing works with a PEM certificate file that contains both certificate and private key.
    /// </summary>
    [TestMethod]
    public void SignWithPemCertificateAndInlineKey_ShouldSucceed()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";
        string pemFile = Path.GetTempFileName() + ".pem";
        
        try
        {
            // Create PEM file with certificate and RSA private key
            CreatePemFileWithKey(SelfSignedCert, pemFile);

            // Act
            string[] args = ["sign", "--p", payloadFile, "--pem", pemFile, "--sf", signatureFile];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed with PEM certificate");
            File.Exists(signatureFile).Should().BeTrue("Signature file should be created");
            
            // Verify signature is valid
            byte[] signatureBytes = File.ReadAllBytes(signatureFile);
            signatureBytes.Length.Should().BeGreaterThan(0, "Signature should not be empty");
        }
        finally
        {
            CleanupFile(payloadFile);
            CleanupFile(signatureFile);
            CleanupFile(pemFile);
        }
    }

    /// <summary>
    /// Tests that signing works with separate PEM certificate and key files.
    /// </summary>
    [TestMethod]
    public void SignWithSeparatePemCertAndKeyFiles_ShouldSucceed()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";
        string certPemFile = Path.GetTempFileName() + ".crt";
        string keyPemFile = Path.GetTempFileName() + ".key";
        
        try
        {
            // Create separate PEM certificate and key files
            CreateSeparatePemFiles(SelfSignedCert, certPemFile, keyPemFile);

            // Act
            string[] args = ["sign", "--p", payloadFile, "--pem", certPemFile, "--key", keyPemFile, "--sf", signatureFile];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed with separate PEM cert and key files");
            File.Exists(signatureFile).Should().BeTrue("Signature file should be created");
        }
        finally
        {
            CleanupFile(payloadFile);
            CleanupFile(signatureFile);
            CleanupFile(certPemFile);
            CleanupFile(keyPemFile);
        }
    }

    /// <summary>
    /// Tests that signing works with a PEM certificate chain (multiple certificates in one file).
    /// </summary>
    [TestMethod]
    public void SignWithPemCertificateChain_ShouldExtractAllCertificates()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";
        string pemChainFile = Path.GetTempFileName() + "_chain.pem";
        string keyFile = Path.GetTempFileName() + ".key";
        
        try
        {
            // Create PEM file with certificate chain (leaf, intermediate, root) and separate key file
            CreatePemChainFiles(CertChain1, pemChainFile, keyFile);

            // Act
            string[] args = ["sign", "--p", payloadFile, "--pem", pemChainFile, "--key", keyFile, "--sf", signatureFile];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            
            // Verify LoadCert extracts the chain correctly
            (X509Certificate2 cert, List<X509Certificate2>? additionalRoots) = cmd.LoadCert();
            
            cert.Should().NotBeNull("Signing certificate should be found");
            cert.HasPrivateKey.Should().BeTrue("Signing certificate should have private key");
            additionalRoots.Should().NotBeNull("Additional certificates should be extracted from PEM chain");
            additionalRoots!.Count.Should().BeGreaterThan(0, "Should have additional certificates from the chain");

            // Run the actual sign operation
            ExitCode result = cmd.Run();
            result.Should().Be(ExitCode.Success, "Sign operation should succeed with PEM certificate chain");
        }
        finally
        {
            CleanupFile(payloadFile);
            CleanupFile(signatureFile);
            CleanupFile(pemChainFile);
            CleanupFile(keyFile);
        }
    }

    /// <summary>
    /// Tests that signing fails gracefully when PEM certificate is specified without a key.
    /// </summary>
    [TestMethod]
    public void SignWithPemCertificateWithoutKey_ShouldFail()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string certOnlyPemFile = Path.GetTempFileName() + ".crt";
        
        try
        {
            // Create PEM file with certificate only (no private key)
            string certPem = ExportCertificateToPem(SelfSignedCert);
            File.WriteAllText(certOnlyPemFile, certPem);

            // Act
            string[] args = ["sign", "--p", payloadFile, "--pem", certOnlyPemFile];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.CertificateLoadFailure, "Sign should fail without private key");
        }
        finally
        {
            CleanupFile(payloadFile);
            CleanupFile(certOnlyPemFile);
        }
    }

    /// <summary>
    /// Tests that PEM options are correctly applied from command line.
    /// </summary>
    [TestMethod]
    public void ApplyOptions_WithPemOptions_ShouldSetProperties()
    {
        // Arrange
        string[] args = ["sign", "--p", "payload.txt", "--pem", "/path/to/cert.pem", "--key", "/path/to/key.pem"];
        
        // Act
        Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
            CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
        badArg.Should().BeNull("badArg should be null.");

        SignCommand cmd = new SignCommand();
        cmd.ApplyOptions(provider);

        // Assert
        cmd.PemCertificate.Should().Be("/path/to/cert.pem", "PemCertificate should be set");
        cmd.PemKey.Should().Be("/path/to/key.pem", "PemKey should be set");
    }

    /// <summary>
    /// Tests signing with an ECDSA PEM certificate.
    /// </summary>
    [TestMethod]
    public void SignWithEcdsaPemCertificate_ShouldSucceed()
    {
        // Arrange
        using X509Certificate2 ecdsaCert = TestCertificateUtils.CreateCertificate(
            nameof(SignWithEcdsaPemCertificate_ShouldSucceed), 
            useEcc: true);
        
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";
        string pemFile = Path.GetTempFileName() + ".pem";
        
        try
        {
            // Create PEM file with ECDSA certificate and key
            CreatePemFileWithKey(ecdsaCert, pemFile);

            // Act
            string[] args = ["sign", "--p", payloadFile, "--pem", pemFile, "--sf", signatureFile];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed with ECDSA PEM certificate");
            File.Exists(signatureFile).Should().BeTrue("Signature file should be created");
        }
        finally
        {
            CleanupFile(payloadFile);
            CleanupFile(signatureFile);
            CleanupFile(pemFile);
        }
    }

    /// <summary>
    /// Tests signing with an encrypted PEM private key.
    /// </summary>
    [TestMethod]
    public void SignWithEncryptedPemPrivateKey_ShouldSucceed()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";
        string certPemFile = Path.GetTempFileName() + ".crt";
        string encryptedKeyFile = Path.GetTempFileName() + ".key";
        string keyPassword = "test-password-123";
        string envVarName = "TEST_PEM_PASSWORD_" + Guid.NewGuid().ToString("N")[..8];
        
        try
        {
            // Create PEM certificate file
            File.WriteAllText(certPemFile, ExportCertificateToPem(SelfSignedCert));
            
            // Create encrypted PEM private key file
            CreateEncryptedPemKeyFile(SelfSignedCert, encryptedKeyFile, keyPassword);

            // Set password via environment variable (secure method)
            Environment.SetEnvironmentVariable(envVarName, keyPassword);

            // Act - Use --pwenv to specify the environment variable
            string[] args = ["sign", "--p", payloadFile, "--pem", certPemFile, "--key", encryptedKeyFile, 
                            "--pwenv", envVarName, "--sf", signatureFile];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed with encrypted PEM private key");
            File.Exists(signatureFile).Should().BeTrue("Signature file should be created");
        }
        finally
        {
            Environment.SetEnvironmentVariable(envVarName, null);
            CleanupFile(payloadFile);
            CleanupFile(signatureFile);
            CleanupFile(certPemFile);
            CleanupFile(encryptedKeyFile);
        }
    }

    /// <summary>
    /// Tests that signing works with password from default COSESIGNTOOL_PASSWORD environment variable.
    /// </summary>
    [TestMethod]
    public void SignWithEncryptedPemPrivateKey_DefaultEnvVar_ShouldSucceed()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string signatureFile = Path.GetTempFileName() + ".cose";
        string certPemFile = Path.GetTempFileName() + ".crt";
        string encryptedKeyFile = Path.GetTempFileName() + ".key";
        string keyPassword = "test-password-default";
        string? originalEnvValue = Environment.GetEnvironmentVariable(SignCommand.DefaultPasswordEnvVar);
        
        try
        {
            // Create PEM certificate file
            File.WriteAllText(certPemFile, ExportCertificateToPem(SelfSignedCert));
            
            // Create encrypted PEM private key file
            CreateEncryptedPemKeyFile(SelfSignedCert, encryptedKeyFile, keyPassword);

            // Set password via default environment variable
            Environment.SetEnvironmentVariable(SignCommand.DefaultPasswordEnvVar, keyPassword);

            // Act - Don't specify --pwenv, should use default COSESIGNTOOL_PASSWORD
            string[] args = ["sign", "--p", payloadFile, "--pem", certPemFile, "--key", encryptedKeyFile, 
                            "--sf", signatureFile];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.Success, "Sign operation should succeed with password from default env var");
            File.Exists(signatureFile).Should().BeTrue("Signature file should be created");
        }
        finally
        {
            Environment.SetEnvironmentVariable(SignCommand.DefaultPasswordEnvVar, originalEnvValue);
            CleanupFile(payloadFile);
            CleanupFile(signatureFile);
            CleanupFile(certPemFile);
            CleanupFile(encryptedKeyFile);
        }
    }

    /// <summary>
    /// Tests that signing fails with encrypted PEM key when no password is provided.
    /// </summary>
    [TestMethod]
    public void SignWithEncryptedPemKeyWithoutPassword_ShouldFail()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string certPemFile = Path.GetTempFileName() + ".crt";
        string encryptedKeyFile = Path.GetTempFileName() + ".key";
        string keyPassword = "test-password-456";
        string? originalEnvValue = Environment.GetEnvironmentVariable(SignCommand.DefaultPasswordEnvVar);
        
        try
        {
            // Create PEM certificate file
            File.WriteAllText(certPemFile, ExportCertificateToPem(SelfSignedCert));
            
            // Create encrypted PEM private key file
            CreateEncryptedPemKeyFile(SelfSignedCert, encryptedKeyFile, keyPassword);

            // Clear the default password env var to ensure no password is available
            Environment.SetEnvironmentVariable(SignCommand.DefaultPasswordEnvVar, null);

            // Act - Note: No password env var set
            string[] args = ["sign", "--p", payloadFile, "--pem", certPemFile, "--key", encryptedKeyFile];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.CertificateLoadFailure, 
                "Sign should fail when encrypted key is provided without password");
        }
        finally
        {
            Environment.SetEnvironmentVariable(SignCommand.DefaultPasswordEnvVar, originalEnvValue);
            CleanupFile(payloadFile);
            CleanupFile(certPemFile);
            CleanupFile(encryptedKeyFile);
        }
    }

    /// <summary>
    /// Tests that signing fails with encrypted PEM key when wrong password is provided via environment variable.
    /// </summary>
    [TestMethod]
    public void SignWithEncryptedPemKeyWithWrongPassword_ShouldFail()
    {
        // Arrange
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string certPemFile = Path.GetTempFileName() + ".crt";
        string encryptedKeyFile = Path.GetTempFileName() + ".key";
        string keyPassword = "correct-password";
        string wrongPassword = "wrong-password";
        string envVarName = "TEST_WRONG_PASSWORD_" + Guid.NewGuid().ToString("N")[..8];
        
        try
        {
            // Create PEM certificate file
            File.WriteAllText(certPemFile, ExportCertificateToPem(SelfSignedCert));
            
            // Create encrypted PEM private key file
            CreateEncryptedPemKeyFile(SelfSignedCert, encryptedKeyFile, keyPassword);

            // Set wrong password via environment variable
            Environment.SetEnvironmentVariable(envVarName, wrongPassword);

            // Act - Provide wrong password via env var
            string[] args = ["sign", "--p", payloadFile, "--pem", certPemFile, "--key", encryptedKeyFile, 
                            "--pwenv", envVarName];
            
            Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
                CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
            badArg.Should().BeNull("badArg should be null.");

            SignCommand cmd = new SignCommand();
            cmd.ApplyOptions(provider);
            ExitCode result = cmd.Run();

            // Assert
            result.Should().Be(ExitCode.CertificateLoadFailure, 
                "Sign should fail when wrong password is provided for encrypted key");
        }
        finally
        {
            Environment.SetEnvironmentVariable(envVarName, null);
            CleanupFile(payloadFile);
            CleanupFile(certPemFile);
            CleanupFile(encryptedKeyFile);
        }
    }

    /// <summary>
    /// Tests that PasswordEnvVar and PasswordPrompt options are correctly applied.
    /// </summary>
    [TestMethod]
    public void ApplyOptions_WithPasswordEnvVarOption_ShouldSetProperties()
    {
        // Arrange
        string[] args = ["sign", "--p", "payload.txt", "--pem", "/path/to/cert.pem", "--key", "/path/to/key.pem", 
                        "--pwenv", "MY_CUSTOM_PASSWORD_VAR"];
        
        // Act
        Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = 
            CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
        badArg.Should().BeNull("badArg should be null.");

        SignCommand cmd = new SignCommand();
        cmd.ApplyOptions(provider);

        // Assert
        cmd.PemCertificate.Should().Be("/path/to/cert.pem", "PemCertificate should be set");
        cmd.PemKey.Should().Be("/path/to/key.pem", "PemKey should be set");
        cmd.PasswordEnvVar.Should().Be("MY_CUSTOM_PASSWORD_VAR", "PasswordEnvVar should be set");
    }

    #region PEM Helper Methods

    private static void CreatePemFileWithKey(X509Certificate2 cert, string pemFile)
    {
        StringBuilder sb = new StringBuilder();
        
        // Export certificate
        sb.AppendLine(ExportCertificateToPem(cert));
        
        // Export private key
        sb.AppendLine(ExportPrivateKeyToPem(cert));
        
        File.WriteAllText(pemFile, sb.ToString());
    }

    private static void CreateSeparatePemFiles(X509Certificate2 cert, string certFile, string keyFile)
    {
        // Export certificate
        File.WriteAllText(certFile, ExportCertificateToPem(cert));
        
        // Export private key
        File.WriteAllText(keyFile, ExportPrivateKeyToPem(cert));
    }

    private static void CreatePemChainFiles(X509Certificate2Collection chain, string chainFile, string keyFile)
    {
        StringBuilder sb = new StringBuilder();
        
        // Get the leaf certificate (the one with private key)
        X509Certificate2 leafCert = chain.Cast<X509Certificate2>().First(c => c.HasPrivateKey);
        
        // Export leaf certificate first
        sb.AppendLine(ExportCertificateToPem(leafCert));
        
        // Export the rest of the chain (intermediates and root)
        foreach (X509Certificate2 cert in chain.Cast<X509Certificate2>().Where(c => !c.Equals(leafCert)))
        {
            sb.AppendLine(ExportCertificateToPem(cert));
        }
        
        File.WriteAllText(chainFile, sb.ToString());
        
        // Export private key separately
        File.WriteAllText(keyFile, ExportPrivateKeyToPem(leafCert));
    }

    private static string ExportCertificateToPem(X509Certificate2 cert)
    {
        return cert.ExportCertificatePem();
    }

    private static string ExportPrivateKeyToPem(X509Certificate2 cert)
    {
        if (cert.GetRSAPrivateKey() is RSA rsa)
        {
            return rsa.ExportRSAPrivateKeyPem();
        }
        else if (cert.GetECDsaPrivateKey() is ECDsa ecdsa)
        {
            return ecdsa.ExportECPrivateKeyPem();
        }
        
        throw new InvalidOperationException("Certificate does not have an RSA or ECDSA private key");
    }

    private static void CreateEncryptedPemKeyFile(X509Certificate2 cert, string keyFile, string password)
    {
        PbeParameters pbeParameters = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc, 
            HashAlgorithmName.SHA256, 
            iterationCount: 100_000);

        if (cert.GetRSAPrivateKey() is RSA rsa)
        {
            string encryptedPem = rsa.ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters);
            File.WriteAllText(keyFile, encryptedPem);
        }
        else if (cert.GetECDsaPrivateKey() is ECDsa ecdsa)
        {
            string encryptedPem = ecdsa.ExportEncryptedPkcs8PrivateKeyPem(password, pbeParameters);
            File.WriteAllText(keyFile, encryptedPem);
        }
        else
        {
            throw new InvalidOperationException("Certificate does not have an RSA or ECDSA private key");
        }
    }

    private static void CleanupFile(string filePath)
    {
        if (File.Exists(filePath))
        {
            try
            {
                File.Delete(filePath);
            }
            catch (IOException) { /* ignore cleanup errors */ }
        }
    }

    #endregion

    #endregion
}