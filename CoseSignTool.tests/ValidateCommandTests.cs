// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

using System;
using System.Linq;
using CoseIndirectSignature;
using CoseSign1.Certificates.Local;
using CoseSignTool.tests;
using CoseX509;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using CST = CoseSignTool.CoseSignTool;

[TestClass]
public class ValidateCommandTests
{
    // Certificates
    private static readonly X509Certificate2 SelfSignedCert = TestCertificateUtils.CreateCertificate(nameof(CoseHandlerSignValidateTests) + " self signed");    // A self-signed cert
    private static readonly X509Certificate2Collection CertChain1 = TestCertificateUtils.CreateTestChain(nameof(CoseHandlerSignValidateTests) + " set 1");      // Two complete cert chains
    private static readonly X509Certificate2Collection CertChain2 = TestCertificateUtils.CreateTestChain(nameof(CoseHandlerSignValidateTests) + " set 2");
    private static readonly X509Certificate2 Root1Priv = CertChain1[0];                                                                                         // Roots from the chains       
    private static readonly X509Certificate2 Root2Priv = CertChain2[0];
    private static readonly X509Certificate2 Int1Priv = CertChain1[1];
    private static readonly X509Certificate2 Leaf1Priv = CertChain1[^1];                                                                                        // Leaf node certs
    private static readonly X509Certificate2 Leaf2Priv = CertChain2[^1];

    // File paths to export them to
    private static readonly string PrivateKeyCertFileSelfSigned = Path.GetTempFileName() + "_SelfSigned.pfx";
    private static readonly string PublicKeyCertFileSelfSigned = Path.GetTempFileName() + "_SelfSigned.cer";
    private static readonly string PrivateKeyRootCertFile = Path.GetTempFileName() + ".pfx";
    private static readonly string PublicKeyIntermediateCertFile = Path.GetTempFileName() + ".cer";
    private static readonly string PublicKeyRootCertFile = Path.GetTempFileName() + ".cer";
    private static readonly string PrivateKeyCertFileChained = Path.GetTempFileName() + ".pfx";
    private static readonly string PrivateKeyCertFileChainedWithPassword = Path.GetTempFileName() + ".pfx";
    private static readonly string CertPassword = Guid.NewGuid().ToString();

    [AssemblyInitialize]
    public static void TestClassInit(TestContext context)
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

    /// <summary>
    /// Validates that signatures made from "untrusted" chains are accepted when root is passed in as trusted
    /// </summary>
    [TestMethod]
    public void ValidateSucceedsWithRootPassedIn()
    {
        string payloadFile = Utils.GetPayloadFile();

        // sign detached
        string[] args1 = { "sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileSelfSigned };
        CST.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign failed.");
        using FileStream coseFile = new(payloadFile + ".cose", FileMode.Open);

        // setup validator
        var validator = new ValidateCommand();
        var result = validator.RunCoseHandlerCommand(coseFile,
                                                     new FileInfo(payloadFile),
                                                     new System.Collections.Generic.List<X509Certificate2> { SelfSignedCert },
                                                     X509RevocationMode.Online,
                                                     null,
                                                     false);
        result.Success.Should().BeTrue();
        result.ContentValidationType.Should().Be(ContentValidationType.Detached);
        result.ToString(true).Should().Contain("Detached");
    }

    /// <summary>
    /// Validates that modified payloads are rejected
    /// </summary>
    [TestMethod]
    public void ValidateFailsWithModifiedPayload()
    {
        string payloadFile = Utils.GetPayloadFile();

        // sign detached
        string[] args1 = { "sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileSelfSigned };
        CST.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign failed.");
        using FileStream coseFile = new(payloadFile + ".cose", FileMode.Open);

        // setup validator
        var validator = new ValidateCommand();
        var result = validator.RunCoseHandlerCommand(coseFile,
                                                     new FileInfo(PublicKeyRootCertFile),
                                                     new System.Collections.Generic.List<X509Certificate2> { SelfSignedCert },
                                                     X509RevocationMode.Online,
                                                     null,
                                                     false);

        result.Success.Should().BeFalse();
        result.Errors.Should().ContainSingle();
        result.Errors[0].ErrorCode.Should().Be(ValidationFailureCode.PayloadMismatch);
        result.ContentValidationType.Should().Be(ContentValidationType.Detached);
        result.ToString(true).Should().Contain("Detached");
    }

    /// <summary>
    /// Validates that signatures made from untrusted chains are accepted when AllowUntrusted is set
    /// </summary>
    [TestMethod]
    public void ValidateSucceedsWithAllowUntrustedRoot()
    {
        string payloadFile = Utils.GetPayloadFile();

        // sign detached
        string[] args1 = { "sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileSelfSigned };
        CST.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign failed.");
        using FileStream coseFile = new(payloadFile + ".cose", FileMode.Open);

        // setup validator
        var validator = new ValidateCommand();
        var result = validator.RunCoseHandlerCommand(coseFile, new FileInfo(payloadFile), null, X509RevocationMode.Online, null, allowUntrusted: true);
        result.Success.Should().BeTrue();
        result.InnerResults.Should().ContainSingle();
        result.InnerResults[0].PassedValidation.Should().BeTrue();
        result.InnerResults[0].ResultMessage.Should().Be("Certificate was allowed because AllowUntrusted was specified.");

        result.ToString(showCertDetails: true).Should().Contain("Certificate chain details");
        result.ContentValidationType.Should().Be(ContentValidationType.Detached);
        result.ToString(true).Should().Contain("Detached");
    }

    /// <summary>
    /// Validates that signatures made from untrusted chains are rejected
    /// </summary>
    [TestMethod]
    public void ValidateUntrustedFails()
    {
        string payloadFile = Utils.GetPayloadFile();

        // sign detached
        string[] args1 = { "sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileSelfSigned };
        CST.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign failed.");
        using FileStream coseFile = new(payloadFile + ".cose", FileMode.Open);

        // setup validator
        var validator = new ValidateCommand();
        var result = validator.RunCoseHandlerCommand(coseFile, new FileInfo(payloadFile), null, X509RevocationMode.Online, null, false);
        result.Success.Should().BeFalse();
        result.Errors.Should().ContainSingle();
        result.Errors[0].ErrorCode.Should().Be(ValidationFailureCode.TrustValidationFailed);

        string resString = result.ToString(verbose: true, showCertDetails: true);
        resString.Should().Contain("Certificate chain details");

        // Content validation type should be set to not performed because we shouldn't try to process untrusted content
        result.ContentValidationType.Should().Be(ContentValidationType.ContentValidationNotPerformed);
        resString.Should().Contain("NotPerformed");
        Console.WriteLine(resString);
    }

    /// <summary>
    /// Validates that signatures made from "untrusted" chains are accepted when root is passed in as trusted
    /// </summary>
    [TestMethod]
    public void ValidateIndirectSucceedsWithRootPassedIn()
    {
        string payloadFile = Utils.GetPayloadFile();

        // sign indirectly
        var msgFac = new IndirectSignatureFactory();
        byte[] signedBytes = msgFac.CreateIndirectSignatureBytes(
        payload: File.ReadAllBytes(payloadFile),
            contentType: "application/spdx+json",
            signingKeyProvider: new X509Certificate2CoseSigningKeyProvider(SelfSignedCert)).ToArray();

        using FileStream coseFile = new(payloadFile + ".cose", FileMode.Create);
        coseFile.Write(signedBytes);
        coseFile.Seek(0, SeekOrigin.Begin);

        // setup validator
        var validator = new ValidateCommand();
        var result = validator.RunCoseHandlerCommand(coseFile,
                                                     new FileInfo(payloadFile),
                                                     new System.Collections.Generic.List<X509Certificate2> { SelfSignedCert },
                                                     X509RevocationMode.Online,
                                                     null,
                                                     false);
        result.Success.Should().BeTrue();
        result.ContentValidationType.Should().Be(ContentValidationType.Indirect);
        result.ToString(true).Should().Contain("Indirect");
    }

    /// <summary>
    /// Validates that indirect signature validation faills when no payload is passed in
    /// </summary>
    [TestMethod]
    public void ValidateIndirectFailsWithoutPayloadPassedIn()
    {
        string payloadFile = Utils.GetPayloadFile();

        // sign indirectly
        var msgFac = new IndirectSignatureFactory();
        byte[] signedBytes = msgFac.CreateIndirectSignatureBytes(
        payload: File.ReadAllBytes(payloadFile),
            contentType: "application/spdx+json",
            signingKeyProvider: new X509Certificate2CoseSigningKeyProvider(SelfSignedCert)).ToArray();

        using FileStream coseFile = new(payloadFile + ".cose", FileMode.Create);
        coseFile.Write(signedBytes);
        coseFile.Seek(0, SeekOrigin.Begin);

        // setup validator
        var validator = new ValidateCommand();
        var result = validator.RunCoseHandlerCommand(coseFile,
                                                     null,
                                                     new System.Collections.Generic.List<X509Certificate2> { SelfSignedCert },
                                                     X509RevocationMode.Online,
                                                     null,
                                                     false);
        result.Success.Should().BeFalse();
        result.ContentValidationType.Should().Be(ContentValidationType.Indirect);
        result.ToString(true).Should().Contain("Indirect");
        result.Errors.Should().ContainSingle();
        result.Errors.FirstOrDefault().ErrorCode.Should().Be(ValidationFailureCode.PayloadMissing);
    }

    /// <summary>
    /// Validates that modified indirect payloads are rejected
    /// </summary>
    public void ValidateIndirectFailsWithModifiedPayload()
    {
        string payloadFile = Utils.GetPayloadFile();

        // sign indirectly
        var msgFac = new IndirectSignatureFactory();
        byte[] signedBytes = msgFac.CreateIndirectSignatureBytes(
        payload: File.ReadAllBytes(payloadFile),
            contentType: "application/spdx+json",
            signingKeyProvider: new X509Certificate2CoseSigningKeyProvider(SelfSignedCert)).ToArray();

        using FileStream coseFile = new(payloadFile + ".cose", FileMode.Create);
        coseFile.Write(signedBytes);
        coseFile.Seek(0, SeekOrigin.Begin);


        // setup validator
        var validator = new ValidateCommand();
        var result = validator.RunCoseHandlerCommand(coseFile,
                                                     new FileInfo(PublicKeyRootCertFile),
                                                     new System.Collections.Generic.List<X509Certificate2> { SelfSignedCert },
                                                     X509RevocationMode.Online,
                                                     null,
                                                     false);
        result.Success.Should().BeFalse();
        result.Errors.Should().ContainSingle();
        result.Errors[0].ErrorCode.Should().Be(ValidationFailureCode.PayloadMismatch);
        result.ContentValidationType.Should().Be(ContentValidationType.Indirect);
        result.ToString(true).Should().Contain("Indirect");
    }

    /// <summary>
    /// Validates that signatures made from untrusted chains are rejected
    /// </summary>
    [TestMethod]
    public void ValidateIndirectFailsWithUntrustedRoot()
    {
        string payloadFile = Utils.GetPayloadFile();

        // sign indirectly
        var msgFac = new IndirectSignatureFactory();
        byte[] signedBytes = msgFac.CreateIndirectSignatureBytes(
        payload: File.ReadAllBytes(payloadFile),
            contentType: "application/spdx+json",
            signingKeyProvider: new X509Certificate2CoseSigningKeyProvider(SelfSignedCert)).ToArray();

        using FileStream coseFile = new(payloadFile + ".cose", FileMode.Create);
        coseFile.Write(signedBytes);
        coseFile.Seek(0, SeekOrigin.Begin);

        // setup validator
        var validator = new ValidateCommand();
        var result = validator.RunCoseHandlerCommand(coseFile,
                                                     new FileInfo(payloadFile),
                                                     null,
                                                     X509RevocationMode.Online,
                                                     null,
                                                     false);
        result.Success.Should().BeFalse();
        result.Errors.Should().ContainSingle();
        result.Errors[0].ErrorCode.Should().Be(ValidationFailureCode.TrustValidationFailed);

        // Content validation type should be set to not performed because we shouldn't try to process untrusted content
        result.ContentValidationType.Should().Be(ContentValidationType.ContentValidationNotPerformed);
        result.ToString(true).Should().Contain("NotPerformed");
    }
}
