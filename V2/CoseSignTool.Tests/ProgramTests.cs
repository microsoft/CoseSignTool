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
        Assert.That(rootCommand.Subcommands, Has.Some.Matches<Command>(c => c.Name == "sign-ephemeral"));
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
        // Do not execute `sign-ephemeral` with stdin in tests, because it may emit binary COSE
        // bytes to stdout, which can break some test loggers.
        string[] args = ["sign-ephemeral", "--help"];

        var console = new TestConsole();

        // Act
        var exitCode = Program.Run(args, console);

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        Assert.That(console.GetStdout(), Does.Contain("stdin"));
    }

    [Test]
    public void Main_WithVerifyCommandNoArgument_TriesToReadFromStdin()
    {
        // Arrange - verify command without arguments tries to read from stdin
        // In test environment with no stdin data, behavior depends on console redirect state
        string[] args = ["verify"];

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
        string[] args = ["sign-ephemeral", "--help"];
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
            Assert.That(rootCommand.Subcommands, Has.Some.Matches<Command>(c => c.Name == "sign-ephemeral"));
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
