// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
}
