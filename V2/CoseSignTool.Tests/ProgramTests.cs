// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests;

using System.CommandLine;
using CoseSignTool.Commands;

/// <summary>
/// Tests for the Program class entry point.
/// </summary>
[TestFixture]
public class ProgramTests
{
    [Test]
    public void Main_WithHelpFlag_ReturnsSuccess()
    {
        // Arrange
        string[] args = ["--help"];
        using var emptyStdin = new MemoryStream();

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithInvalidCommand_ReturnsInvalidArguments()
    {
        // Arrange
        string[] args = ["invalid-command"];
        using var emptyStdin = new MemoryStream();

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.InvalidArguments));
    }

    [Test]
    public void Main_WithNullArgs_ThrowsArgumentNullException()
    {
        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => Program.Main(null!));
    }

    [Test]
    public void Main_WithNullElementInArgs_ReturnsGeneralErrorAndWritesFatalError()
    {
        // A string[] can legally contain null at runtime; System.CommandLine isn't expected to handle this.
        // We verify Program catches unexpected exceptions and returns a general error.
        string[] args = [null!];

        var console = new TestConsole();
        var exitCode = Program.Run(args, console);

        Assert.That(exitCode, Is.EqualTo((int)ExitCode.GeneralError));
        Assert.That(console.GetStderr(), Does.Contain("Fatal error:"));
    }

    [Test]
    public void CreateRootCommand_ReturnsConfiguredCommand()
    {
        // Act
        var console = new TestConsole();
        var builder = new CommandBuilder(console, null);
        var rootCommand = builder.BuildRootCommand();

        // Assert
        Assert.That(rootCommand, Is.Not.Null);
        Assert.That(rootCommand, Is.InstanceOf<RootCommand>());
        Assert.That(rootCommand.Subcommands, Is.Not.Empty);
    }

    [Test]
    public void CreateRootCommand_HasSignEphemeralCommand()
    {
        // Act
        var console = new TestConsole();
        var builder = new CommandBuilder(console, null);
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var sign = rootCommand.Subcommands.FirstOrDefault(c => c.Name == "sign");
        Assert.That(sign, Is.Not.Null);

        var x509 = sign!.Subcommands.FirstOrDefault(c => c.Name == "x509");
        Assert.That(x509, Is.Not.Null);

        Assert.That(x509!.Subcommands, Has.Some.Matches<Command>(c => c.Name == "ephemeral"));
    }

    [Test]
    public void CreateRootCommand_HasVerifyCommand()
    {
        // Act
        var console = new TestConsole();
        var builder = new CommandBuilder(console, null);
        var rootCommand = builder.BuildRootCommand();

        // Assert
        Assert.That(rootCommand.Subcommands, Has.Some.Matches<Command>(c => c.Name == "verify"));
    }

    [Test]
    public void CreateRootCommand_HasInspectCommand()
    {
        // Act
        var console = new TestConsole();
        var builder = new CommandBuilder(console, null);
        var rootCommand = builder.BuildRootCommand();

        // Assert
        Assert.That(rootCommand.Subcommands, Has.Some.Matches<Command>(c => c.Name == "inspect"));
    }

    [Test]
    public void ExtractAdditionalPluginDirectories_RemovesArgsAndReturnsDirectories()
    {
        // Arrange
        var tempDir = Path.Combine(Path.GetTempPath(), $"plugins_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        string[] args = [
            "--additional-plugin-dir",
            tempDir,
            "--help"
        ];

        var method = typeof(Program).GetMethod(
            "ExtractAdditionalPluginDirectories",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        Assert.That(method, Is.Not.Null);

        try
        {
            var parameters = new object[] { args };

            // Act
            var dirs = (List<string>)method!.Invoke(null, parameters)!;
            var remainingArgs = (string[])parameters[0];

            // Assert
            Assert.That(dirs, Is.EquivalentTo(new[] { tempDir }));
            Assert.That(remainingArgs, Is.EquivalentTo(new[] { "--help" }));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public void Main_WithSignEphemeralHelp_ShowsStdinUsage()
    {
        // Arrange
        // Do not execute signing with stdin in tests, because it may emit binary COSE
        // bytes to stdout, which can break some test loggers.
        string[] args = ["sign", "x509", "ephemeral", "--help"];

        var console = new TestConsole();

        // Act
        var exitCode = Program.Run(args, console);

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        var output = console.GetStdout() + console.GetStderr();
        Assert.That(output, Does.Contain("stdin"));
        Assert.That(output, Does.Not.Contain("sign-ephemeral"));
    }

    [Test]
    public void Main_WithVerifyCommandNoArgument_TriesToReadFromStdin()
    {
        // Arrange - verify command with no signature tries to read from stdin.
        // With fix-forward CLI, verification root is required.
        // In test environment with no stdin data, behavior depends on console redirect state.
        string[] args = ["verify", "x509"];

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert - In test environment, stdin behavior varies
        // - FileNotFound (3): No data on stdin (detected empty)
        // - Success (0): Empty stdin handled gracefully
        // - 1: System.CommandLine parse errors can vary by environment
        Assert.That(exitCode == (int)ExitCode.FileNotFound ||
                exitCode == (int)ExitCode.Success ||
                exitCode == 1,
                    Is.True,
                $"Expected FileNotFound (3), Success (0), or 1, got {exitCode}");
    }

    [Test]
    public void Main_WithVersionFlag_ReturnsSuccess()
    {
        // Arrange
        string[] args = ["--version"];
        using var emptyStdin = new MemoryStream();

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithSignEphemeralHelpFlag_ReturnsSuccess()
    {
        // Arrange
        string[] args = ["sign", "x509", "ephemeral", "--help"];
        using var emptyStdin = new MemoryStream();

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithVerifyHelpFlag_ReturnsSuccess()
    {
        // Arrange
        string[] args = ["verify", "--help"];
        using var emptyStdin = new MemoryStream();

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void VerifyHelp_ShowsAvailableTrustRoots()
    {
        // Arrange
        var console = new TestConsole();
        string[] args = ["verify", "--help"];

        // Act
        var exitCode = Program.Run(args, console);
        var output = console.GetStdout() + console.GetStderr();

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        Assert.That(output, Does.Contain("Commands:")
            .Or.Contain("COMMANDS:"));
        Assert.That(output, Does.Contain("x509"));
        Assert.That(output, Does.Contain("mst"));
        Assert.That(output, Does.Contain("akv"));
    }

    [Test]
    public void VerifyHelp_ForMstRoot_ShowsMstOptions()
    {
        // Arrange
        var console = new TestConsole();
        string[] args = ["verify", "mst", "--help"];

        // Act
        var exitCode = Program.Run(args, console);
        var output = console.GetStdout() + console.GetStderr();

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        Assert.That(output, Does.Contain("--mst-offline-keys"));
        Assert.That(output, Does.Contain("--mst-trust-ledger-instance"));
        // MST-specific options should be present; X.509 certificate options should not be present
        Assert.That(output, Does.Not.Contain("--trust-roots"));
        Assert.That(output, Does.Not.Contain("--allow-untrusted"));
        Assert.That(output, Does.Not.Contain("--revocation-mode"));
    }

    [Test]
    public void VerifyHelp_ForX509Root_ShowsX509OptionsOnly()
    {
        // Arrange
        var console = new TestConsole();
        string[] args = ["verify", "x509", "--help"];

        // Act
        var exitCode = Program.Run(args, console);
        var output = console.GetStdout() + console.GetStderr();

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        Assert.That(output, Does.Contain("--trust-roots"));
        Assert.That(output, Does.Not.Contain("--mst-offline-keys"));
    }

    [Test]
    public void SignHelp_ShowsAvailableSigningRoots()
    {
        // Arrange
        var console = new TestConsole();
        string[] args = ["sign", "--help"];

        // Act
        var exitCode = Program.Run(args, console);
        var output = console.GetStdout() + console.GetStderr();

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        Assert.That(output, Does.Contain("Commands:")
            .Or.Contain("COMMANDS:"));
        Assert.That(output, Does.Contain("x509"));
        Assert.That(output, Does.Contain("akv"));
    }

    [Test]
    public void SignHelp_WithX509Selected_ShowsX509Providers()
    {
        // Arrange
        var console = new TestConsole();
        string[] args = ["sign", "x509", "--help"];

        // Act
        var exitCode = Program.Run(args, console);
        var output = console.GetStdout() + console.GetStderr();

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        Assert.That(output, Does.Contain("pfx"));
        Assert.That(output, Does.Not.Contain("akv-key"));
    }

    [Test]
    public void SignHelp_WithAkvSelected_ShowsAkvProvidersOnly()
    {
        // Arrange
        var console = new TestConsole();
        string[] args = ["sign", "akv", "--help"];

        // Act
        var exitCode = Program.Run(args, console);
        var output = console.GetStdout() + console.GetStderr();

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        Assert.That(output, Does.Contain("akv-key"));
        Assert.That(output, Does.Not.Contain("pfx"));
    }

    [Test]
    public void SignHelp_WithProviderSelected_ShowsProviderHelp()
    {
        // Arrange
        var console = new TestConsole();
        string[] args = ["sign", "x509", "ephemeral", "--help"];

        // Act
        var exitCode = Program.Run(args, console);
        var output = console.GetStdout() + console.GetStderr();

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        Assert.That(output, Does.Contain("Usage:"));
        Assert.That(output, Does.Contain("sign x509 ephemeral"));
        Assert.That(output, Does.Not.Contain("sign-ephemeral"));
    }

    [Test]
    public void SignHelp_WithAkvProviderSelected_ShowsProviderHelp()
    {
        // Arrange
        var console = new TestConsole();
        string[] args = ["sign", "akv", "akv-key", "--help"];

        // Act
        var exitCode = Program.Run(args, console);
        var output = console.GetStdout() + console.GetStderr();

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        Assert.That(output, Does.Contain("Usage:"));
        Assert.That(output, Does.Contain("sign akv akv-key")
            .Or.Contain("sign akv key"));
        Assert.That(output, Does.Not.Contain("sign-akv-key"));
    }

    [Test]
    public void Main_WithInspectHelpFlag_ReturnsSuccess()
    {
        // Arrange
        string[] args = ["inspect", "--help"];
        using var emptyStdin = new MemoryStream();

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithOutputFormatOption_AcceptsJson()
    {
        // Arrange
        string[] args = ["--output-format", "json", "--help"];
        using var emptyStdin = new MemoryStream();

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithOutputFormatOption_AcceptsXml()
    {
        // Arrange
        string[] args = ["--output-format", "xml", "--help"];
        using var emptyStdin = new MemoryStream();

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithOutputFormatOption_AcceptsQuiet()
    {
        // Arrange
        string[] args = ["--output-format", "quiet", "--help"];
        using var emptyStdin = new MemoryStream();

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithShortOutputFormatOption_AcceptsText()
    {
        // Arrange
        string[] args = ["-f", "text", "--help"];
        using var emptyStdin = new MemoryStream();

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithEmptyArgs_ReturnsSuccess()
    {
        // Arrange - no args shows help
        string[] args = [];
        using var emptyStdin = new MemoryStream();

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert - no arguments shows help and returns success
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void CreateRootCommand_WithAdditionalPluginDirectories_DoesNotThrow()
    {
        // Arrange
        var tempDir = Path.Combine(Path.GetTempPath(), $"test_plugins_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            // Act
            var console = new TestConsole();
            var builder = new CommandBuilder(console, null);
            var rootCommand = builder.BuildRootCommand([tempDir]);

            // Assert
            Assert.That(rootCommand, Is.Not.Null);

            var sign = rootCommand.Subcommands.FirstOrDefault(c => c.Name == "sign");
            Assert.That(sign, Is.Not.Null);

            var x509 = sign!.Subcommands.FirstOrDefault(c => c.Name == "x509");
            Assert.That(x509, Is.Not.Null);

            Assert.That(x509!.Subcommands, Has.Some.Matches<Command>(c => c.Name == "ephemeral"));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public void CreateRootCommand_WithNull_DoesNotThrow()
    {
        // Act
        var console = new TestConsole();
        var builder = new CommandBuilder(console, null);
        var rootCommand = builder.BuildRootCommand(null);

        // Assert
        Assert.That(rootCommand, Is.Not.Null);
    }

    [Test]
    public void Main_WithAdditionalPluginDir_ProcessesPluginDirectory()
    {
        // Arrange
        var tempDir = Path.Combine(Path.GetTempPath(), $"test_plugins_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            string[] args = ["--additional-plugin-dir", tempDir, "--help"];
            using var emptyStdin = new MemoryStream();

            // Act
            var exitCode = Program.Run(args, new TestConsole());

            // Assert
            Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public void Main_WithInspectCommandNoArgument_TriesToReadFromStdin()
    {
        // Arrange - inspect command without arguments tries to read from stdin
        // In test environment with no stdin data, behavior depends on console redirect state
        string[] args = ["inspect"];

        // Act
        var exitCode = Program.Run(args, new TestConsole());

        // Assert - In test environment, stdin behavior varies
        // - FileNotFound (3): No data on stdin (detected empty)
        // - Success (0): Empty stdin handled gracefully
        // - InvalidArguments (1): Program parsing reports no argument provided
        Assert.That(exitCode == (int)ExitCode.FileNotFound ||
                    exitCode == (int)ExitCode.Success ||
                    exitCode == 1, // System.CommandLine may return 1 for various reasons
                    Is.True,
                    $"Expected FileNotFound (3), Success (0), or 1, got {exitCode}");
    }
}
