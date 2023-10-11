// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

using System;
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
    private static readonly string PrivateKeyCertFileSelfSigned = Path.GetTempFileName()    + "_SelfSigned.pfx";
    private static readonly string PublicKeyCertFileSelfSigned = Path.GetTempFileName() + "_SelfSigned.cer";
    private static readonly string PrivateKeyRootCertFile = Path.GetTempFileName() + ".pfx";
    private static readonly string PublicKeyIntermediateCertFile = Path.GetTempFileName() + ".cer";
    private static readonly string PublicKeyRootCertFile = Path.GetTempFileName() + ".cer";
    private static readonly string PrivateKeyCertFileChained = Path.GetTempFileName() + ".pfx";
    private static readonly string PrivateKeyCertFileChainedWithPassword = Path.GetTempFileName() + ".pfx";
    private static readonly string CertPassword = Guid.NewGuid().ToString();


    private static string PayloadFile;
    private static readonly byte[] Payload1Bytes = Encoding.ASCII.GetBytes("Payload1!");

    public MainTests()
    {
        // make payload file
        PayloadFile = Path.GetTempFileName();
        File.WriteAllBytes(PayloadFile, Payload1Bytes);

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

        // sign detached
        string[] args1 = { "sign", @"/p", PayloadFile, @"/pfx", PrivateKeyCertFileChained };
        CST.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign failed.");

        // sign embedded
        string[] args2 = { "sign", @"/pfx", PrivateKeyCertFileChained, @"/p", PayloadFile, @"/ep" };
        CST.Main(args2).Should().Be((int)ExitCode.Success, "Embed sign failed.");

        // validate detached
        string sigFile = PayloadFile + ".cose";
        string[] args3 = { "validate", @"/rt", certPair, @"/sf", sigFile, @"/p", PayloadFile, "/rm", "NoCheck" };
        CST.Main(args3).Should().Be((int)ExitCode.Success, "Detach validation failed.");

        // validate embedded
        sigFile = PayloadFile + ".csm";
        string[] args4 = { "validate", @"/rt", certPair, @"/sf", sigFile, "/rm", "NoCheck" };
        CST.Main(args4).Should().Be((int)ExitCode.Success, "Embed validation failed.");

        // get content
        string saveFile = PayloadFile + ".saved";
        string[] args5 = { "get", @"/rt", certPair, @"/sf", sigFile, "/sa", saveFile, "/rm", "NoCheck" };
        CST.Main(args5).Should().Be(0, "Detach validation with save failed.");
        File.ReadAllText(PayloadFile).Should().Be(File.ReadAllText(saveFile), "Saved content did not match payload.");
    }

    [TestMethod]
    public void SignWithPasswordProtectedCertSuccess()
    {
        // sign detached with password protected cert
        string[] args1 = { "sign", @"/p", PayloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword };
        CST.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign with password protected cert failed.");
    }

    [TestMethod]
    public void SignWithPasswordProtectedCertNoPassword()
    {
        // sign detached with password protected cert
        string[] args1 = { "sign", @"/p", PayloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword };
        CST.Main(args1).Should().Be((int)ExitCode.CertificateLoadFailure, "Detach sign did not fail in the expected way.");
    }

    [TestMethod]
    public void SignWithPasswordProtectedCertWrongPassword()
    {
        // sign detached with password protected cert
        string[] args1 = { "sign", @"/p", PayloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", "NotThePassword" };
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

        // nonexistent payload file
        string[] args4 = { "sign", @"/pfx", "fake.pfx", @"/p", "asdfa" };
        CST.Main(args4).Should().Be((int)ExitCode.UserSpecifiedFileNotFound);

        // missing cert
        string sigFile = Path.GetTempFileName();
        string payload = Path.GetTempFileName();
        string[] args5 = { "validate", @"/rt", payload, @"/sf", sigFile, @"/rt", "cert.wacky" };
        CST.Main(args5).Should().Be((int)ExitCode.CertificateLoadFailure);
    }
}