// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests;

[TestClass]
public class CoseCommandTests
{
    private static readonly string WindowsFilePath1 = @"c:\some.file";
    private static readonly string WindowsFilePath2 = @"c:\another.file";
    private static readonly string LinuxFilePath1 = @"/home/some.file";
    private static readonly string LinuxFilePath2 = @"/home/another.file";
    private static readonly string FilePath1 = OperatingSystem.IsWindows() ? WindowsFilePath1 : LinuxFilePath1;
    private static readonly string FilePath2 = OperatingSystem.IsWindows() ? WindowsFilePath2 : LinuxFilePath2;

    [TestMethod]
    public void SetAllOptionTypesDashSpace()
    {
        string[] args = ["-PfxCertificate", "fake.pfx", "-Payload", FilePath1, "-EmbedPayload", "-sf", FilePath2];

        Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
        badArg.Should().BeNull("badArg should be null.");

        SignCommand cmd1 = new SignCommand();
        cmd1.ApplyOptions(provider);

        cmd1.PfxCertificate.Should().Be("fake.pfx");
        cmd1.PayloadFile!.FullName.Should().Be(FilePath1);
        cmd1.EmbedPayload.Should().BeTrue();


        string[] args2 = ["-Payload", FilePath1, "-roots", "asd.cer, wer.cer, rtg.cer, xcv.cer, 234.cer", "-sf", FilePath2];
        Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider2 = CoseCommand.LoadCommandLineArgs(args2, ValidateCommand.Options, out badArg)!;
        badArg.Should().BeNull("badArg should be null.");

        ValidateCommand cmd2 = new ValidateCommand();
        cmd2.ApplyOptions(provider2);
        cmd2.Roots.Should().BeEquivalentTo(["asd.cer", "wer.cer", "rtg.cer", "xcv.cer", "234.cer"], options => options.WithStrictOrdering());
    }

    [TestMethod]
    public void LoadFromAliases()
    {
        string[] args = ["-p", FilePath1, "-rt", "asd.cer, wer.cer, rtg.cer, xcv.cer, 234.cer", "-sf", FilePath2];

        Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = CoseCommand.LoadCommandLineArgs(args, ValidateCommand.Options, out string? badArg)!;
        badArg.Should().BeNull("badArg should be null.");

        ValidateCommand cmd1 = new ValidateCommand();
        cmd1.ApplyOptions(provider);

        cmd1.PayloadFile!.FullName.Should().Be(FilePath1);
        cmd1.SignatureFile!.FullName.Should().Be(FilePath2);

        cmd1.Roots.Should().BeEquivalentTo(["asd.cer", "wer.cer", "rtg.cer", "xcv.cer", "234.cer"], options => options.WithStrictOrdering());
    }

    [TestMethod]
    public void SlashAndDash()
    {
        string[] args = ["/PfxCertificate", "fake.pfx", "-Payload", FilePath1, "/EmbedPayload", "-sf", FilePath2];
        Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out _)!;
        SignCommand cmd1 = new SignCommand();

        cmd1.ApplyOptions(provider);

        cmd1.PayloadFile!.FullName.Should().Be(FilePath1);
        cmd1.EmbedPayload.Should().Be(true);
        cmd1.PfxCertificate.Should().Be("fake.pfx");
    }

    [TestMethod]
    public void LoadCommandLineArgs()
    {
        string[] args = ["-PfxCertificate", "fake.pfx", "-Payload", FilePath1 , "-embedpayload", "-sf", FilePath2];

        Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;

        badArg.Should().BeNull("badArg should be null.");

        SignCommand cmd1 = new SignCommand();
        cmd1.ApplyOptions(provider);
    }

    [TestMethod]
    public void LoadCommandLineArgsWithColons()
    {
        string[] args = ["-PfxCertificate:fake.pfx", @"-Payload:c:\some.file", "-embedpayload", @"-sf:c:\another.file"];
        Microsoft.Extensions.Configuration.CommandLine.CommandLineConfigurationProvider provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string? badArg)!;
        badArg.Should().BeNull("badArg should be null.");
        SignCommand cmd1 = new SignCommand();
        cmd1.ApplyOptions(provider);
    }
}
