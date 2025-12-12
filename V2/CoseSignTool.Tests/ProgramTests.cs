// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Commands;
using System.CommandLine;

namespace CoseSignTool.Tests;

/// <summary>
/// Tests for the Program class entry point.
/// </summary>
public class ProgramTests
{
    [Fact]
    public void Main_WithHelpFlag_ReturnsSuccess()
    {
        // Arrange
        string[] args = ["--help"];

        // Act
        var exitCode = Program.Main(args);

        // Assert
        exitCode.Should().Be((int)ExitCode.Success);
    }

    [Fact]
    public void Main_WithInvalidCommand_ReturnsInvalidArguments()
    {
        // Arrange
        string[] args = ["invalid-command"];

        // Act
        var exitCode = Program.Main(args);

        // Assert
        exitCode.Should().Be((int)ExitCode.InvalidArguments);
    }

    [Fact]
    public void Main_WithNullArgs_ThrowsArgumentNullException()
    {
        // Act
        Action act = () => Program.Main(null!);

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void CreateRootCommand_ReturnsConfiguredCommand()
    {
        // Act
        var rootCommand = Program.CreateRootCommand();

        // Assert
        rootCommand.Should().NotBeNull();
        rootCommand.Should().BeOfType<RootCommand>();
        rootCommand.Subcommands.Should().NotBeEmpty();
    }

    [Fact]
    public void CreateRootCommand_HasSignCommand()
    {
        // Act
        var rootCommand = Program.CreateRootCommand();

        // Assert
        rootCommand.Subcommands.Should().Contain(c => c.Name == "sign");
    }

    [Fact]
    public void CreateRootCommand_HasVerifyCommand()
    {
        // Act
        var rootCommand = Program.CreateRootCommand();

        // Assert
        rootCommand.Subcommands.Should().Contain(c => c.Name == "verify");
    }

    [Fact]
    public void CreateRootCommand_HasInspectCommand()
    {
        // Act
        var rootCommand = Program.CreateRootCommand();

        // Assert
        rootCommand.Subcommands.Should().Contain(c => c.Name == "inspect");
    }

    [Fact]
    public void Main_WithSignCommandMissingArgument_ReturnsInvalidArguments()
    {
        // Arrange - sign command requires a payload argument
        string[] args = ["sign"];

        // Act
        var exitCode = Program.Main(args);

        // Assert
        exitCode.Should().Be((int)ExitCode.InvalidArguments);
    }

    [Fact]
    public void Main_WithVerifyCommandMissingArgument_ReturnsInvalidArguments()
    {
        // Arrange - verify command requires a signature argument
        string[] args = ["verify"];

        // Act
        var exitCode = Program.Main(args);

        // Assert
        exitCode.Should().Be((int)ExitCode.InvalidArguments);
    }
}
