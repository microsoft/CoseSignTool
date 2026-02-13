// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests;

[TestClass]
public class MainTests
{
    // Certificates
    private static readonly X509Certificate2 SelfSignedCert = TestCertificateUtils.CreateCertificate(nameof(MainTests) + " self signed");    // A self-signed cert
    private static readonly X509Certificate2Collection CertChain1 = TestCertificateUtils.CreateTestChain(nameof(MainTests) + " set 1");      // Two complete cert chains
    private static readonly X509Certificate2 Root1Priv = CertChain1[0];                                                                                         // Roots from the chains
    private static readonly X509Certificate2 Int1Priv = CertChain1[1];
    private static readonly X509Certificate2 Leaf1Priv = CertChain1[^1];                                                                                        // Leaf node certs

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

        // sign detached - explicitly specify signature file to avoid collision with embedded
        string detachedSigFile = payloadFile + ".detached.cose";
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChained, @"/sf", detachedSigFile];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.Success, "Detach sign should have succeeded.");

        // sign embedded - explicitly specify signature file to avoid collision with detached
        string embeddedSigFile = payloadFile + ".embedded.cose";
        string[] args2 = ["sign", @"/pfx", PrivateKeyCertFileChained, @"/p", payloadFile, @"/ep", @"/sf", embeddedSigFile];
        CoseSignTool.Main(args2).Should().Be((int)ExitCode.Success, "Embed sign should have succeeded.");

        // validate detached
        string[] args3 = ["validate", @"/rt", certPair, @"/sf", detachedSigFile, @"/p", payloadFile, "/rm", "NoCheck"];
        CoseSignTool.Main(args3).Should().Be((int)ExitCode.Success, "Detach validation should have succeeded.");

        // validate embedded
        string[] args4 = ["validate", @"/rt", certPair, @"/sf", embeddedSigFile, "/rm", "NoCheck", "/scd"];
        CoseSignTool.Main(args4).Should().Be((int)ExitCode.Success, "Embed validation should have succeeded.");

        // get content
        string saveFile = payloadFile + ".saved";
        string[] args5 = ["get", @"/rt", certPair, @"/sf", embeddedSigFile, "/sa", saveFile, "/rm", "NoCheck"];
        CoseSignTool.Main(args5).Should().Be(0, "Detach validation with save should have suceeded.");
        File.ReadAllText(payloadFile).Should().Be(File.ReadAllText(saveFile), "Saved content should have matched payload.");
    }

    [TestMethod]
    public void FromMainValidationStdOut()
    {
        // capture stdout and stderr
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

        // Filter out plugin loading warnings (these can occur due to static state across tests)
        string stderrContent = redirectedErr.ToString();
        string[] stderrLines = stderrContent.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        string[] actualErrors = stderrLines.Where(line => !line.StartsWith("Warning: Command '") || !line.Contains("conflicts with an existing command")).ToArray();
        actualErrors.Should().BeEmpty("There should be no errors (excluding plugin conflict warnings from test infrastructure).");
        
        string stdoutContent = redirectedOut.ToString();
        stdoutContent.Should().Contain("Validation succeeded.", "Validation should succeed.");
        stdoutContent.Should().Contain("validation type: Detached", "Validation type should be detached.");
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

        // missing certificate - no pfx or thumbprint provided
        // This results in CertificateLoadFailure because LoadCert() throws ArgumentNullException
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string[] args3 = ["sign", @"/p", payloadFile];
        CoseSignTool.Main(args3).Should().Be((int)ExitCode.CertificateLoadFailure);
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
         CoseSignTool.Main(args1).Should().Be((int)ExitCode.FileUnreadable);

        // empty signature file
        string[] args2 = ["validate", @"/rt", PublicKeyRootCertFile, @"/sf", emptyFile, "/rm", "NoCheck", "/scd"];
        CoseSignTool.Main(args2).Should().Be((int)ExitCode.FileUnreadable);
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

    [TestMethod]
    public void SignWithIntegerHeadersSuccess()
    {
        string integerHeadersFile = FileSystemUtils.GenerateHeadersFile(@"[{""label"":""created-at"",""value"":1723588348,""protected"":true}]");
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign with integer headers
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/ih", integerHeadersFile];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.Success, "Payload must be signed.");
    }

    [TestMethod]
    public void SignWithMissingValueIntegerHeaders()
    {
        string integerHeadersFile = FileSystemUtils.GenerateHeadersFile(@"[{""label"":""created-at"",""value"":,""protected"":true}]");
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign with integer headers
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/ih", integerHeadersFile];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.InvalidArgumentValue, "Invalid integer header value.");
    }

    [TestMethod]
    public void SignWithOutOfRangeValueIntegerHeaders()
    {
        string integerHeadersFile = FileSystemUtils.GenerateHeadersFile(@"[{""label"":""created-at"",""value"":-999999999999999,""protected"":true}]");
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign with integer headers
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/ih", integerHeadersFile];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.InvalidArgumentValue, "Invalid integer header value.");
    }

    [TestMethod]
    public void SignWithDeserializationErrorIntegerHeaders()
    {
        string integerHeadersFile = FileSystemUtils.GenerateHeadersFile(@"[{""label"":""created-at"",XXX:-999999999999999,""protected"":true}]");
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign with integer headers
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/ih", integerHeadersFile];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.InvalidArgumentValue, "Integer headers file deserialization error.");
    }

    [TestMethod]
    public void SignWithMissingIntegerHeadersFile()
    {
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign with integer headers
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/ih"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UserSpecifiedFileNotFound, "Missing integer headers file.");
    }

    [TestMethod]
    public void SignWithMissingStringHeadersFile()
    {
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign with string headers
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/sh"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UserSpecifiedFileNotFound, "Missing string headers file.");
    }

    [TestMethod]
    public void SignWithMissingValueStringHeaders()
    {
        string headersFile = FileSystemUtils.GenerateHeadersFile(@"[{""label"":""created-at"",""value"":"""",""protected"":false}]");
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign with string headers
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/sh", headersFile];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.MissingRequiredOption, "Missing value in string headers file.");
    }

    [TestMethod]
    public void SignWithDeserializationErrorStringHeaders()
    {
        string headersFile = FileSystemUtils.GenerateHeadersFile(@"[{""label"":""created-at"",YYY:""invalid"",""protected"":false}]");
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign with string headers
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/sh", headersFile];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.InvalidArgumentValue, "String headers file could not be deserialized.");
    }

    [TestMethod]
    public void SignWithCommandLineIntAndStringHeaders()
    {
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // sign with int protected headers
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/sph", "sph1=sphv1,sph2=sphv2", @"/iph", "iph1=12345,iph2=123"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.Success, "Signing with protected int headers in command line failed.");

        // sign with int and string unprotected headers
        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/suh", "suh1=testsigning,suh2=value2", @"/iuh", "iuh1=12345,iuh2=123"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.Success, "Signing with int and string unprotected headers in command line failed.");

        // sign with string unprotected headers
        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/suh", "suh3=testsigning,suh4=value2"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.Success, "Signing with unprotected string headers in command line failed.");

        // sign with string protected headers
        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/sph", "sph3=testsigning"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.Success, "Signing with protected string headers in command line failed.");
    }

    [TestMethod]
    public void SignWithMissingAndInvalidCommandLineHeaders()
    {
        string payloadFile = FileSystemUtils.GeneratePayloadFile();

        // protected int headers
        string[] args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/iph", "created-at=,"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with missing int value in int protected headers in command line succeeded.");

        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/iph"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with missing int headers in int protected headers in command line succeeded.");

        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/iph", "created-at=abc"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with invalid int value in headers in int protected headers in command line succeeded.");

        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/iph", "created-at"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with missing int value in headers in int protected headers in command line succeeded.");

        // protected string headers
        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/sph", "message-type=,"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with missing string value in string protected headers in command line succeeded.");

        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/sph"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with missing string headers in string protected headers in command line succeeded.");

        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/iph", "message-type"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with missing string value in headers in string protected headers in command line succeeded.");

        // unprotected int headers
        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/iuh", "created-at=,"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with missing int value in int unprotected headers in command line succeeded.");

        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/iuh"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with missing int headers in int unprotected headers in command line succeeded.");

        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/iuh", "created-at=abc"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with invalid int value in headers in int unprotected headers in command line succeeded.");

        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/iuh", "created-at"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with missing int value in headers in int unprotected headers in command line succeeded.");

        // unprotected string headers
        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/suh", "message-type=,"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with missing string value in string unprotected headers in command line succeeded.");

        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/suh"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with missing string headers in string unprotected headers in command line succeeded.");

        args1 = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChainedWithPassword, @"/pw", CertPassword, @"/ep", @"/iuh", "message-type"];
        CoseSignTool.Main(args1).Should().Be((int)ExitCode.UnknownError, "Signing with missing string value in headers in string unprotected headers in command line succeeded.");
    }

    [TestMethod]
    public void HelpCommand_WithNoArguments_ShowsGeneralHelp()
    {
        // Arrange & Act
        string[] args = ["help"];
        int result = CoseSignTool.Main(args);

        // Assert
        result.Should().Be((int)ExitCode.HelpRequested, "Help command without arguments should show general help");
    }

    [TestMethod]
    public void HelpCommand_WithProviderName_ShowsProviderHelp()
    {
        // Note: This test won't find any providers since we're not in a plugins directory,
        // but it exercises the ShowProviderHelp code path
        string[] args = ["help", "test-provider"];
        int result = CoseSignTool.Main(args);

        // The result will be MissingRequiredOption because the provider doesn't exist
        result.Should().Be((int)ExitCode.MissingRequiredOption, "Help command with non-existent provider should return error");
    }

    [TestMethod]
    public void IsNullOrHelp_WithNullArg_ReturnsTrue()
    {
        // Use reflection to test the private IsNullOrHelp method
        var method = typeof(CoseSignTool).GetMethod("IsNullOrHelp", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        var result = (bool)method!.Invoke(null, new object?[] { null })!;
        result.Should().BeTrue("Null argument should be considered as help request");
    }

    [TestMethod]
    public void IsNullOrHelp_WithQuestionMark_ReturnsTrue()
    {
        // Use reflection to test the private IsNullOrHelp method
        var method = typeof(CoseSignTool).GetMethod("IsNullOrHelp", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        var result = (bool)method!.Invoke(null, new object?[] { "sign?" })!;
        result.Should().BeTrue("Argument ending with '?' should be considered as help request");
    }

    [TestMethod]
    public void IsNullOrHelp_WithHelp_ReturnsTrue()
    {
        // Use reflection to test the private IsNullOrHelp method
        var method = typeof(CoseSignTool).GetMethod("IsNullOrHelp", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        var result = (bool)method!.Invoke(null, new object?[] { "help" })!;
        result.Should().BeTrue("'help' argument should be considered as help request");
    }

    [TestMethod]
    public void IsNullOrHelp_WithCaseInsensitiveHelp_ReturnsTrue()
    {
        // Use reflection to test the private IsNullOrHelp method
        var method = typeof(CoseSignTool).GetMethod("IsNullOrHelp", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        var result = (bool)method!.Invoke(null, new object?[] { "HELP" })!;
        result.Should().BeTrue("'HELP' (uppercase) argument should be considered as help request");
    }

    [TestMethod]
    public void IsNullOrHelp_WithNormalArg_ReturnsFalse()
    {
        // Use reflection to test the private IsNullOrHelp method
        var method = typeof(CoseSignTool).GetMethod("IsNullOrHelp", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        var result = (bool)method!.Invoke(null, new object?[] { "sign" })!;
        result.Should().BeFalse("Normal argument should not be considered as help request");
    }

    [TestMethod]
    public void Fail_WithException_WritesToErrorOutput()
    {
        // Arrange - capture stderr
        using StringWriter redirectedErr = new();
        Console.SetError(redirectedErr);

        Exception testException = new InvalidOperationException("Test error message");

        // Act
        ExitCode result = CoseSignTool.Fail(ExitCode.UnknownError, testException, "Custom message");

        // Assert
        result.Should().Be(ExitCode.UnknownError);
        string errorOutput = redirectedErr.ToString();
        errorOutput.Should().Contain("Test error message");
        errorOutput.Should().Contain("Custom message");
    }

    [TestMethod]
    public void Fail_WithNullException_WritesCustomMessage()
    {
        // Arrange - capture stderr
        using StringWriter redirectedErr = new();
        Console.SetError(redirectedErr);

        // Act
        ExitCode result = CoseSignTool.Fail(ExitCode.MissingRequiredOption, null, "Missing required option message");

        // Assert
        result.Should().Be(ExitCode.MissingRequiredOption);
        string errorOutput = redirectedErr.ToString();
        errorOutput.Should().Contain("Missing required option message");
    }

    [TestMethod]
    public void Usage_WithBadArg_ReturnsUnknownArgument()
    {
        // Arrange - capture stdout
        using StringWriter redirectedOut = new();
        Console.SetOut(redirectedOut);

        // Act
        ExitCode result = CoseSignTool.Usage("Usage information", "/badArg");

        // Assert
        result.Should().Be(ExitCode.UnknownArgument);
        string output = redirectedOut.ToString();
        output.Should().Contain("/badArg");
        output.Should().Contain("Usage information");
    }

    [TestMethod]
    public void Usage_WithoutBadArg_ReturnsHelpRequested()
    {
        // Arrange - capture stdout
        using StringWriter redirectedOut = new();
        Console.SetOut(redirectedOut);

        // Act
        ExitCode result = CoseSignTool.Usage("Usage information");

        // Assert
        result.Should().Be(ExitCode.HelpRequested);
        string output = redirectedOut.ToString();
        output.Should().Contain("Usage information");
        output.Should().NotContain("Error:");
    }

    [TestMethod]
    public void Main_WithHelpAfterVerb_ShowsVerbSpecificHelp()
    {
        // Arrange & Act
        string[] args = ["sign", "help"];
        int result = CoseSignTool.Main(args);

        // Assert
        result.Should().Be((int)ExitCode.HelpRequested, "Help after verb should show verb-specific help");
    }

    [TestMethod]
    public void Main_WithQuestionMarkAfterVerb_ShowsVerbSpecificHelp()
    {
        // Arrange & Act
        string[] args = ["validate", "?"];
        int result = CoseSignTool.Main(args);

        // Assert
        result.Should().Be((int)ExitCode.HelpRequested, "Question mark after verb should show verb-specific help");
    }

    [TestMethod]
    public void Main_WithGetVerb_ShowsGetHelp()
    {
        // Arrange & Act
        string[] args = ["get"];
        int result = CoseSignTool.Main(args);

        // Assert
        result.Should().Be((int)ExitCode.HelpRequested, "Get verb without arguments should show help");
    }

    [TestMethod]
    public void Main_WithValidateVerb_ShowsValidateHelp()
    {
        // Arrange & Act
        string[] args = ["validate"];
        int result = CoseSignTool.Main(args);

        // Assert
        result.Should().Be((int)ExitCode.HelpRequested, "Validate verb without arguments should show help");
    }

    [TestMethod]
    public void Main_WithUnknownVerb_ShowsGeneralHelp()
    {
        // Arrange & Act
        string[] args = ["unknownverb"];
        int result = CoseSignTool.Main(args);

        // Assert
        result.Should().Be((int)ExitCode.HelpRequested, "Unknown verb should show general help");
    }

    #region Piping Tests

    /// <summary>
    /// Tests that piping works end-to-end by running actual process with redirected streams.
    /// Simulates: gc mycontent | cosesigntool sign -pfx cert.pfx -ep -po | cosesigntool validate -rt roots.cer
    /// </summary>
    [TestMethod]
    public void EndToEndPipelineWithActualProcess()
    {
        // Arrange - create test payload
        string payloadContent = "Test payload content for piped signing " + Guid.NewGuid();
        byte[] payloadBytes = System.Text.Encoding.UTF8.GetBytes(payloadContent);

        string exePath = Path.Join(AppContext.BaseDirectory, "CoseSignTool.dll");
        
        // Step 1: Sign with piped payload (embedded signature so payload is included)
        byte[] signatureBytes;
        using (var signProcess = new Process())
        {
            signProcess.StartInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"\"{exePath}\" sign /pfx \"{PrivateKeyCertFileChained}\" /po /ep",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            signProcess.Start();
            
            // Write payload to stdin
            signProcess.StandardInput.BaseStream.Write(payloadBytes, 0, payloadBytes.Length);
            signProcess.StandardInput.Close();

            // Read signature from stdout
            using MemoryStream ms = new();
            signProcess.StandardOutput.BaseStream.CopyTo(ms);
            signatureBytes = ms.ToArray();
            
            signProcess.WaitForExit(30000);
            
            string stderr = signProcess.StandardError.ReadToEnd();
            signProcess.ExitCode.Should().Be(0, $"Sign process should succeed. StdErr: {stderr}");
        }

        signatureBytes.Should().NotBeEmpty("Signature should be produced");

        // Step 2: Validate with piped embedded signature
        string certPair = $"{PublicKeyIntermediateCertFile}, {PublicKeyRootCertFile}";
        using (var validateProcess = new Process())
        {
            validateProcess.StartInfo = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"\"{exePath}\" validate /rt \"{certPair}\" /rm NoCheck",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            validateProcess.Start();
            
            // Write signature to stdin
            validateProcess.StandardInput.BaseStream.Write(signatureBytes, 0, signatureBytes.Length);
            validateProcess.StandardInput.Close();

            string stdout = validateProcess.StandardOutput.ReadToEnd();
            string stderr = validateProcess.StandardError.ReadToEnd();
            
            validateProcess.WaitForExit(30000);
            
            validateProcess.ExitCode.Should().Be(0, $"Validate process should succeed. StdOut: {stdout}, StdErr: {stderr}");
            stdout.Should().Contain("Validation succeeded", "Output should indicate success");
        }
    }

    /// <summary>
    /// Tests detached signature validation with piped signature and file-based payload.
    /// Simulates: gc detached.cose | cosesigntool validate -p payload.txt -rt roots.cer
    /// </summary>
    [TestMethod]
    public void ValidateDetachedSignatureWithPipedSignatureAndPayloadFile()
    {
        // Arrange - create signature file first
        string certPair = $"{PublicKeyIntermediateCertFile}, {PublicKeyRootCertFile}";
        string payloadFile = FileSystemUtils.GeneratePayloadFile();
        string sigFile = payloadFile + ".detached.cose";

        // Create detached signature using file I/O
        string[] signArgs = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChained, @"/sf", sigFile];
        CoseSignTool.Main(signArgs).Should().Be((int)ExitCode.Success, "Detached sign should succeed");

        // Read signature for piping
        byte[] signatureBytes = File.ReadAllBytes(sigFile);

        string exePath = Path.Join(AppContext.BaseDirectory, "CoseSignTool.dll");
        
        // Validate with piped signature
        using var validateProcess = new Process();
        validateProcess.StartInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"\"{exePath}\" validate /p \"{payloadFile}\" /rt \"{certPair}\" /rm NoCheck",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        validateProcess.Start();
        
        // Write signature to stdin
        validateProcess.StandardInput.BaseStream.Write(signatureBytes, 0, signatureBytes.Length);
        validateProcess.StandardInput.Close();

        string stdout = validateProcess.StandardOutput.ReadToEnd();
        string stderr = validateProcess.StandardError.ReadToEnd();
        
        validateProcess.WaitForExit(30000);
        
        validateProcess.ExitCode.Should().Be(0, $"Validate with piped detached signature should succeed. StdOut: {stdout}, StdErr: {stderr}");
        stdout.Should().Contain("Validation succeeded", "Output should indicate success");

        // Cleanup
        File.Delete(payloadFile);
        File.Delete(sigFile);
    }

    /// <summary>
    /// Tests get command with piped embedded signature.
    /// Simulates: gc embedded.cose | cosesigntool get -rt roots.cer
    /// Get command writes to stdout by default (no -po needed, unlike sign command)
    /// </summary>
    [TestMethod]
    public void GetContentFromPipedEmbeddedSignature()
    {
        // Arrange - create embedded signature file first
        string certPair = $"{PublicKeyIntermediateCertFile}, {PublicKeyRootCertFile}";
        string payloadContent = "Unique payload for get test " + Guid.NewGuid();
        string payloadFile = Path.GetTempFileName();
        File.WriteAllText(payloadFile, payloadContent);
        string sigFile = payloadFile + ".embedded.cose";

        // Create embedded signature using file I/O
        string[] signArgs = ["sign", @"/p", payloadFile, @"/pfx", PrivateKeyCertFileChained, @"/ep", @"/sf", sigFile];
        CoseSignTool.Main(signArgs).Should().Be((int)ExitCode.Success, "Embedded sign should succeed");

        // Read signature for piping
        byte[] signatureBytes = File.ReadAllBytes(sigFile);

        string exePath = Path.Join(AppContext.BaseDirectory, "CoseSignTool.dll");
        
        // Get content with piped signature(get writes to stdout by default when -sa not specified)
        using var getProcess = new Process();
        getProcess.StartInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"\"{exePath}\" get /rt \"{certPair}\" /rm NoCheck",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        getProcess.Start();
        
        // Write signature to stdin
        getProcess.StandardInput.BaseStream.Write(signatureBytes, 0, signatureBytes.Length);
        getProcess.StandardInput.Close();

        using MemoryStream outputMs = new();
        getProcess.StandardOutput.BaseStream.CopyTo(outputMs);
        string extractedContent = System.Text.Encoding.UTF8.GetString(outputMs.ToArray());
        string stderr = getProcess.StandardError.ReadToEnd();
        
        getProcess.WaitForExit(30000);
        
        getProcess.ExitCode.Should().Be(0, $"Get from piped embedded signature should succeed. StdErr: {stderr}");
        extractedContent.Should().Contain(payloadContent, "Extracted content should contain original payload");

        // Cleanup
        File.Delete(payloadFile);
        File.Delete(sigFile);
    }

    #endregion
}
