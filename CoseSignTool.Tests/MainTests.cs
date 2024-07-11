// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests;

[TestClass]
public class MainTests
{
    // Certificates
    private static readonly X509Certificate2 SelfSignedCert = TestCertificateUtils.CreateCertificate(nameof(MainTests) + " self signed");    // A self-signed cert
    private static readonly X509Certificate2Collection CertChain1 = TestCertificateUtils.CreateTestChain(nameof(MainTests) + " set 1");      // Two complete cert chains
    private static readonly X509Certificate2Collection CertChain2 = TestCertificateUtils.CreateTestChain(nameof(MainTests) + " set 2");
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
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign detached
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChained];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign should have succeeded.");

        // sign embedded
        string[] args2 = ["sign", @"/pfx", PrivateKeyCertFileChained, @"/p", payloadFile, @"/ep"];
        CoseSignTool.Main(args2).Should().Be((int)ExitCode.Success, "Embed sign should have succeeded.");

        // validate detached
        string sigFile = payloadFile + ".cose";
        string[] args3 = ["validate", @"/rt", certPair, @"/sf", sigFile, @"/p", payloadFile, "/rm", "NoCheck"];
        CoseSignTool.Main(args3).Should().Be((int)ExitCode.Success, "Detach validation should have succeeded.");

        // validate embedded
        sigFile = payloadFile + ".csm";
        string[] args4 = ["validate", @"/rt", certPair, @"/sf", sigFile, "/rm", "NoCheck", "/scd"];
        CoseSignTool.Main(args4).Should().Be((int)ExitCode.Success, "Embed validation should have succeeded.");

        // get content
        string saveFile = payloadFile + ".saved";
        string[] args5 = ["get", @"/rt", certPair, @"/sf", sigFile, "/sa", saveFile, "/rm", "NoCheck"];
        CoseSignTool.Main(args5).Should().Be(0, "Detach validation with save should have suceeded.");
        File.ReadAllText(payloadFile).Should().Be(File.ReadAllText(saveFile), "Saved content should have matched payload.");
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
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign detached
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChained];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign should have succeeded.");

        // validate detached
        string sigFile = payloadFile + ".cose";
        string[] args3 = ["validate", @"/rt", certPair, @"/sf", sigFile, @"/p", payloadFile, "/rm", "NoCheck"];
        CoseSignTool.Main(args3).Should().Be((int)ExitCode.Success, "Detach validation should have succeeded.");

        redirectedErr.ToString().Should().BeEmpty("There should be no errors.");
        redirectedOut.ToString().Should().Contain("Validation succeeded.", "Validation should succeed.");
        redirectedOut.ToString().Should().Contain("validation type: Detached", "Validation type should be detached.");
    }

    [TestMethod]
    public void SignWithPasswordProtectedCertSuccess()
    {
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        // sign detached with password protected cert
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign with password protected cert should have succeeded.");
    }

    [TestMethod]
    public void SignWithPasswordProtectedCertNoPassword()
    {
        // sign detached with password protected cert
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.CertificateLoadFailure, "Detach sign should have failed with CertificateLoadFailure.");
    }

    [TestMethod]
    public void SignWithPasswordProtectedCertWrongPassword()
    {
        // sign detached with password protected cert
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", "NotThePassword"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.CertificateLoadFailure, "Detach sign should have failed with CertificateLoadFailure.");
    }

    [TestMethod]
    public void FromMainInvalid()
    {
        // no verb
        string[] args1 = [@"/pfx", "fake.pfx", @"/p", "some.file"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.HelpRequested);

        // bad argument
        string[] args2 = ["sign", "/badArg", @"/pfx", "fake.pfx", @"/p", "some.file"];
        CoseSignTool.Main(args2).Should().Be((int)ExitCode.UnknownArgument);

        // empty payload argument
        string[] args3 = ["sign", @"/pfx", "fake.pfx", @"/p", ""];
        CoseSignTool.Main(args3).Should().Be((int)ExitCode.MissingRequiredOption);
    }

    [TestMethod]
    public void FileNotFound()
    {
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string missingFile = @"c:\NoFileHere.nothing";
        string sigFile = $"{payloadFile}.cose";
        CoseSignTool.Main(["sign", @"/pfx", PrivateKeyCertFileChained, @"/p", payloadFile]);

        // missing payload file - sign
        string[] argsMissingPayloadFileSign = ["sign", @"/pfx", PrivateKeyCertFileChained, @"/p", missingFile];
        CoseSignTool.Main(argsMissingPayloadFileSign).Should().Be((int)ExitCode.UserSpecifiedFileNotFound);

        // missing payload file - validate
        string[] argsMissingPayloadFileValidate = ["validate", @"/sf", sigFile, @"/p", missingFile, @"/rt", PublicKeyRootCertFile];
        CoseSignTool.Main(argsMissingPayloadFileValidate).Should().Be((int)ExitCode.UserSpecifiedFileNotFound);

        // missing cert
        string[] argsMissingCert = ["validate", @"/sf", sigFile, @"/p", payloadFile, @"/rt", missingFile];
        CoseSignTool.Main(argsMissingCert).Should().Be((int)ExitCode.CertificateLoadFailure);

        // missing signature file
        string[] argsMissingSigFile = ["validate", @"/sf", missingFile, @"/p", payloadFile, @"/rt", PublicKeyRootCertFile];
        CoseSignTool.Main(argsMissingSigFile).Should().Be((int)ExitCode.UserSpecifiedFileNotFound);
    }

    [TestMethod]
    public void ValidateSameFileMultipleTimesMain() // This is to make sure file handles are getting released when they should
    {
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string sigFile = $"{payloadFile}.cose";
        string certPair = $"\"{PublicKeyIntermediateCertFile}, {PublicKeyRootCertFile}\"";

        // sign detached
        string[] signArgs = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChained];
        CoseSignTool.Main(signArgs).Should().Be((int)ExitCode.Success, "Detach sign should have succeeded.");

        // validate detached
        string[] validateArgs = ["validate", @"/rt", certPair, @"/sf", sigFile, @"/p", payloadFile, "/rm", "NoCheck"];
        CoseSignTool.Main(validateArgs).Should().Be((int)ExitCode.Success, "Validation should have succeeded the first time.");

        // validate detached again
        CoseSignTool.Main(validateArgs).Should().Be((int)ExitCode.Success, "Validation should have succeeded the second time");

        // validate detached a third time
        CoseSignTool.Main(validateArgs).Should().Be((int)ExitCode.Success, "Validation should have succeeded the third time");
    }

    [TestMethod]
    public void EmptySourceFile()
    {
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string emptyFile = Path.GetTempFileName();
        File.WriteAllBytes(payloadFile, []);

        // empty payload file
        string[] args1 = ["sign", @"/pfx", "fake.pfx", @"/p", emptyFile];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.EmptySourceFile);

        // empty signature file
        string[] args2 = ["validate", @"/rt", PublicKeyRootCertFile, @"/sf", emptyFile, "/rm", "NoCheck", "/scd"];
        CoseSignTool.Main(args2).Should().Be((int)ExitCode.EmptySourceFile);
    }

    [TestMethod]
    public void ReturnsHelpRequestedWhenVerbMissing()
    {
        string[] args = [];
        CoseSignTool.Main(args).Should().Be((int)ExitCode.HelpRequested);
    }

    [TestMethod]
    public void ReturnsHelpRequestedWhenNoOptionsAfterVerb()
    {
        string[] args = [ "sign" ];
        CoseSignTool.Main(args).Should().Be((int)ExitCode.HelpRequested);
    }
}