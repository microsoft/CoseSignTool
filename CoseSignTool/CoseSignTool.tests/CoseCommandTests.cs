// ---------------------------------------------------------------------------
// <copyright file="CoseCommandTests.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseSignUnitTests;

[TestClass]
public class CoseCommandTests
{

    [TestMethod]
    public void SetAllOptionTypesDashSpace()
    {
        string[] args = { "-PfxCertificate", "fake.pfx", "-Payload", @"c:\some.file", "-EmbedPayload", "-sf", @"c:\another.file" };

        var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string badArg);
        badArg.Should().BeNull("badArg should be null.");

        var cmd1 = new SignCommand();
        cmd1.ApplyOptions(provider);

        cmd1.PfxCertificate.Should().Be("fake.pfx");
        cmd1.PayloadFile.FullName.Should().Be(@"c:\some.file");
        cmd1.EmbedPayload.Should().BeTrue();


        string[] args2 = { "-Payload", @"c:\some.file", "-roots", "asd.cer, wer.cer, rtg.cer, xcv.cer, 234.cer", "-sf", @"c:\another.file" };
        var provider2 = CoseCommand.LoadCommandLineArgs(args2, ValidateCommand.Options, out badArg);
        badArg.Should().BeNull("badArg should be null.");

        var cmd2 = new ValidateCommand();
        cmd2.ApplyOptions(provider2);
        cmd2.Roots.Should().BeEquivalentTo(new string[] { "asd.cer", "wer.cer", "rtg.cer", "xcv.cer", "234.cer" }, options => options.WithStrictOrdering());
    }

    [TestMethod]
    public void LoadFromAliases()
    {
        string[] args = { "-p", @"c:\some.file", "-rt", "asd.cer, wer.cer, rtg.cer, xcv.cer, 234.cer", "-sf", @"c:\another.file" };

        var provider = CoseCommand.LoadCommandLineArgs(args, ValidateCommand.Options, out string badArg);
        badArg.Should().BeNull("badArg should be null.");

        var cmd1 = new ValidateCommand();
        cmd1.ApplyOptions(provider);

        cmd1.PayloadFile.FullName.Should().Be(@"c:\some.file");
        cmd1.SignatureFile.FullName.Should().Be(@"c:\another.file");

        cmd1.Roots.Should().BeEquivalentTo(new string[] { "asd.cer", "wer.cer", "rtg.cer", "xcv.cer", "234.cer" }, options => options.WithStrictOrdering());
    }

    [TestMethod]
    public void SlashAndDash()
    {
        string[] args = { "/PfxCertificate", "fake.pfx", "-Payload", @"c:\some.file", "/EmbedPayload", "-sf", @"c:\another.file" };
        var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out _);
        var cmd1 = new SignCommand();

        cmd1.ApplyOptions(provider);

        cmd1.PayloadFile.FullName.Should().Be(@"c:\some.file");
        cmd1.EmbedPayload.Should().Be(true);
        cmd1.PfxCertificate.Should().Be("fake.pfx");
    }

    [TestMethod]
    public void LoadCommandLineArgs()
    {
        string[] args = { "-PfxCertificate", "fake.pfx", "-Payload", @"c:\some.file", "-embedpayload", "-sf", @"c:\another.file" };

        var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string badArg);

        badArg.Should().BeNull("badArg should be null.");

        var cmd1 = new SignCommand();
        cmd1.ApplyOptions(provider);
    }

    [TestMethod]
    public void LoadCommandLineArgsWithColons()
    {
        string[] args = { "-PfxCertificate:fake.pfx", @"-Payload:c:\some.file", "-embedpayload", @"-sf:c:\another.file" };
        var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string badArg);
        badArg.Should().BeNull("badArg should be null.");
        var cmd1 = new SignCommand();
        cmd1.ApplyOptions(provider);
    }
}
