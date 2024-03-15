// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

using System;
using CoseSignTool.tests;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using CST = CoseSignTool.CoseSignTool;

[TestClass]
public class MainTests
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

    public MainTests()
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
    public void FromMainValid()
    {
        string certPair = $"\"{PublicKeyIntermediateCertFile}, {PublicKeyRootCertFile}\"";
        string payloadFile = Utils.GetPayloadFile();

        // sign detached
        string[] args1 = { "sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChained };
        CST.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign failed.");

        // sign embedded
        string[] args2 = { "sign", @"/pfx", PrivateKeyCertFileChained, @"/p", payloadFile, @"/ep" };
        CST.Main(args2).Should().Be((int)ExitCode.Success, "Embed sign failed.");

        // validate detached
        string sigFile = payloadFile + ".cose";
        string[] args3 = { "validate", @"/rt", certPair, @"/sf", sigFile, @"/p", payloadFile, "/rm", "NoCheck" };
        CST.Main(args3).Should().Be((int)ExitCode.Success, "Detach validation failed.");

        // validate embedded
        sigFile = payloadFile + ".csm";
        string[] args4 = { "validate", @"/rt", certPair, @"/sf", sigFile, "/rm", "NoCheck", "/scd" };
        CST.Main(args4).Should().Be((int)ExitCode.Success, "Embed validation failed.");

        // get content
        string saveFile = payloadFile + ".saved";
        string[] args5 = { "get", @"/rt", certPair, @"/sf", sigFile, "/sa", saveFile, "/rm", "NoCheck" };
        CST.Main(args5).Should().Be(0, "Detach validation with save failed.");
        File.ReadAllText(payloadFile).Should().Be(File.ReadAllText(saveFile), "Saved content did not match payload.");
    }

    [TestMethod]
    public void FromMainValidationStdOut()
    {
        // caprture stdout and stderr
        using StringWriter redirectedOut = new();
        using StringWriter redirectedErr = new();
        Console.SetOut(redirectedOut);
        Console.SetError(redirectedErr);

        string certPair = $"\"{PublicKeyIntermediateCertFile}, {PublicKeyRootCertFile}\"";
        string payloadFile = Utils.GetPayloadFile();

        // sign detached
        string[] args1 = { "sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChained };
        CST.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign failed.");

        // validate detached
        string sigFile = payloadFile + ".cose";
        string[] args3 = { "validate", @"/rt", certPair, @"/sf", sigFile, @"/p", payloadFile, "/rm", "NoCheck" };
        CST.Main(args3).Should().Be((int)ExitCode.Success, "Detach validation failed.");

        redirectedErr.ToString().Should().BeEmpty("There should be no errors.");
        redirectedOut.ToString().Should().Contain("Validation succeeded.", "Validation should succeed.");
        redirectedOut.ToString().Should().Contain("validation type: Detached", "Validation type should be detached.");
    }

    [TestMethod]
    public void SignWithPasswordProtectedCertSuccess()
    {
        string payloadFile = Utils.GetPayloadFile();
        // sign detached with password protected cert
        string[] args1 = { "sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword };
        CST.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign with password protected cert failed.");
    }

    [TestMethod]
    public void SignWithPasswordProtectedCertNoPassword()
    {
        // sign detached with password protected cert
        string payloadFile = Utils.GetPayloadFile();
        string[] args1 = { "sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword };
        CST.Main(args1).Should().Be((int)ExitCode.CertificateLoadFailure, "Detach sign did not fail in the expected way.");
    }

    [TestMethod]
    public void SignWithPasswordProtectedCertWrongPassword()
    {
        // sign detached with password protected cert
        string payloadFile = Utils.GetPayloadFile();
        string[] args1 = { "sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", "NotThePassword" };
        CST.Main(args1).Should().Be((int)ExitCode.CertificateLoadFailure, "Detach sign did not fail in the expected way.");
    }

    [TestMethod]
    public void FromMainInvalid()
    {
        // no verb
        string[] args1 = { @"/pfx", "fake.pfx", @"/p", "some.file" };
        CST.Main(args1).Should().Be((int)ExitCode.HelpRequested);

        // bad argument
        string[] args2 = { "sign", "/badArg", @"/pfx", "fake.pfx", @"/p", "some.file" };
        CST.Main(args2).Should().Be((int)ExitCode.UnknownArgument);

        // empty payload argument
        string[] args3 = { "sign", @"/pfx", "fake.pfx", @"/p", "" };
        CST.Main(args3).Should().Be((int)ExitCode.MissingRequiredOption);
    }

    [TestMethod]
    public void FileNotFound()
    {
        string payloadFile = Utils.GetPayloadFile();
        string missingFile = @"c:\NoFileHere.nothing";
        string sigFile = $"{payloadFile}.cose";
        CST.Main(new string[] { "sign", @"/pfx", PrivateKeyCertFileChained, @"/p", payloadFile });

        // missing payload file - sign
        string[] args1 = { "sign", @"/pfx", PrivateKeyCertFileChained, @"/p", missingFile };
        CST.Main(args1).Should().Be((int)ExitCode.UserSpecifiedFileNotFound);

        // missing payload file - validate
        string[] args2 = { "validate", @"/sf", sigFile, @"/p", missingFile, @"/rt", PublicKeyRootCertFile };
        CST.Main(args2).Should().Be((int)ExitCode.UserSpecifiedFileNotFound);

        // missing signature file
        string[] args3 = { "validate", @"/sf", missingFile, @"/p", payloadFile, @"/rt", PublicKeyRootCertFile };
        CST.Main(args3).Should().Be((int)ExitCode.UserSpecifiedFileNotFound);

        // missing cert
        string[] args6 = { "validate", @"/sf", sigFile, @"/p", payloadFile, @"/rt", missingFile };
        CST.Main(args6).Should().Be((int)ExitCode.CertificateLoadFailure);
    }

    [TestMethod]
    public void EmptySourceFile()
    {
        string payloadFile = Utils.GetPayloadFile();
        string emptyFile = Path.GetTempFileName();
        File.WriteAllBytes(payloadFile, Array.Empty<byte>());

        // empty payload file
        string[] args1 = { "sign", @"/pfx", "fake.pfx", @"/p", emptyFile };
        CST.Main(args1).Should().Be((int)ExitCode.EmptySourceFile);

        // empty signature file
        string[] args2 = { "validate", @"/rt", PublicKeyRootCertFile, @"/sf", emptyFile, "/rm", "NoCheck", "/scd" };
        CST.Main(args2).Should().Be((int)ExitCode.EmptySourceFile);
    }

    [TestMethod]
    public void ReturnsHelpRequestedWhenVerbMissing()
    {
        string[] args = Array.Empty<string>();
        CST.Main(args).Should().Be((int)ExitCode.HelpRequested);
    }

    [TestMethod]
    public void ReturnsHelpRequestedWhenNoOptionsAfterVerb()
    {
        string[] args = Array.Empty<string>();
        CST.Main(args).Should().Be((int)ExitCode.HelpRequested);
    }
}