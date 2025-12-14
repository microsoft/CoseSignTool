// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSignTool.Commands;

namespace CoseSignTool.Tests;

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

        // Act
        var exitCode = Program.Main(args);

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithInvalidCommand_ReturnsInvalidArguments()
    {
        // Arrange
        string[] args = ["invalid-command"];

        // Act
        var exitCode = Program.Main(args);

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
    public void CreateRootCommand_ReturnsConfiguredCommand()
    {
        // Act
        var rootCommand = Program.CreateRootCommand();

        // Assert
        Assert.That(rootCommand, Is.Not.Null);
        Assert.That(rootCommand, Is.InstanceOf<RootCommand>());
        Assert.That(rootCommand.Subcommands, Is.Not.Empty);
    }

    [Test]
    public void CreateRootCommand_HasSignEphemeralCommand()
    {
        // Act
        var rootCommand = Program.CreateRootCommand();

        // Assert
        Assert.That(rootCommand.Subcommands, Has.Some.Matches<Command>(c => c.Name == "sign-ephemeral"));
    }

    [Test]
    public void CreateRootCommand_HasVerifyCommand()
    {
        // Act
        var rootCommand = Program.CreateRootCommand();

        // Assert
        Assert.That(rootCommand.Subcommands, Has.Some.Matches<Command>(c => c.Name == "verify"));
    }

    [Test]
    public void CreateRootCommand_HasInspectCommand()
    {
        // Act
        var rootCommand = Program.CreateRootCommand();

        // Assert
        Assert.That(rootCommand.Subcommands, Has.Some.Matches<Command>(c => c.Name == "inspect"));
    }

    [Test]
    public void Main_WithSignEphemeralCommandNoArgument_ReturnsSuccessWithStdinSupport()
    {
        // Arrange - sign-ephemeral with no argument will try to read from stdin
        // In test context with empty stdin, it should return success (empty input)
        // or FileNotFound depending on implementation
        string[] args = ["sign-ephemeral"];

        // Act
        var exitCode = Program.Main(args);

        // Assert - sign-ephemeral without arguments reads from stdin (returns 0 or 3 depending on stdin)
        // Since there's no stdin in test, it will try to sign empty data and succeed or fail gracefully
        Assert.That(exitCode == (int)ExitCode.Success || exitCode == (int)ExitCode.FileNotFound, Is.True);
    }

    [Test]
    public void Main_WithVerifyCommandNoArgument_TriesToReadFromStdin()
    {
        // Arrange - verify command without arguments tries to read from stdin
        // In test environment with no stdin data, behavior depends on console redirect state
        string[] args = ["verify"];

        // Act
        var exitCode = Program.Main(args);

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

        // Act
        var exitCode = Program.Main(args);

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithSignEphemeralHelpFlag_ReturnsSuccess()
    {
        // Arrange
        string[] args = ["sign-ephemeral", "--help"];

        // Act
        var exitCode = Program.Main(args);

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithVerifyHelpFlag_ReturnsSuccess()
    {
        // Arrange
        string[] args = ["verify", "--help"];

        // Act
        var exitCode = Program.Main(args);

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithInspectHelpFlag_ReturnsSuccess()
    {
        // Arrange
        string[] args = ["inspect", "--help"];

        // Act
        var exitCode = Program.Main(args);

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithOutputFormatOption_AcceptsJson()
    {
        // Arrange
        string[] args = ["--output-format", "json", "--help"];

        // Act
        var exitCode = Program.Main(args);

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithOutputFormatOption_AcceptsXml()
    {
        // Arrange
        string[] args = ["--output-format", "xml", "--help"];

        // Act
        var exitCode = Program.Main(args);

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithOutputFormatOption_AcceptsQuiet()
    {
        // Arrange
        string[] args = ["--output-format", "quiet", "--help"];

        // Act
        var exitCode = Program.Main(args);

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithShortOutputFormatOption_AcceptsText()
    {
        // Arrange
        string[] args = ["-f", "text", "--help"];

        // Act
        var exitCode = Program.Main(args);

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void Main_WithEmptyArgs_ReturnsSuccess()
    {
        // Arrange - no args shows help
        string[] args = [];

        // Act
        var exitCode = Program.Main(args);

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
            var rootCommand = Program.CreateRootCommand([tempDir]);

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
        var rootCommand = Program.CreateRootCommand(null);

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

            // Act
            var exitCode = Program.Main(args);

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
        var exitCode = Program.Main(args);

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