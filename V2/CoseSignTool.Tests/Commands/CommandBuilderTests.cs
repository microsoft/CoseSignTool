// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Commands;
using System.CommandLine;

namespace CoseSignTool.Tests.Commands;

/// <summary>
/// Tests for the CommandBuilder class.
/// </summary>
public class CommandBuilderTests
{
    [Fact]
    public void BuildRootCommand_ReturnsRootCommand()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        rootCommand.Should().NotBeNull();
        rootCommand.Should().BeOfType<RootCommand>();
    }

    [Fact]
    public void BuildRootCommand_HasCorrectDescription()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        rootCommand.Description.Should().Contain("COSE Sign1");
    }

    [Fact]
    public void BuildRootCommand_HasSignCommand()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var signCommand = rootCommand.Subcommands.FirstOrDefault(c => c.Name == "sign");
        signCommand.Should().NotBeNull();
    }

    [Fact]
    public void BuildRootCommand_HasVerifyCommand()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var verifyCommand = rootCommand.Subcommands.FirstOrDefault(c => c.Name == "verify");
        verifyCommand.Should().NotBeNull();
    }

    [Fact]
    public void BuildRootCommand_HasInspectCommand()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var inspectCommand = rootCommand.Subcommands.FirstOrDefault(c => c.Name == "inspect");
        inspectCommand.Should().NotBeNull();
    }

    [Fact]
    public void BuildRootCommand_SignCommandHasRequiredPayloadArgument()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign");

        // Assert
        var payloadArg = signCommand.Arguments.FirstOrDefault(a => a.Name == "payload");
        payloadArg.Should().NotBeNull();
        payloadArg!.Arity.MinimumNumberOfValues.Should().Be(1);
    }

    [Fact]
    public void BuildRootCommand_SignCommandHasOutputOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign");

        // Assert
        var outputOption = signCommand.Options.FirstOrDefault(o => o.Name == "output");
        outputOption.Should().NotBeNull();
    }

    [Fact]
    public void BuildRootCommand_SignCommandHasDetachedOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign");

        // Assert
        var detachedOption = signCommand.Options.FirstOrDefault(o => o.Name == "detached");
        detachedOption.Should().NotBeNull();
    }

    [Fact]
    public void BuildRootCommand_VerifyCommandHasRequiredSignatureArgument()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var verifyCommand = rootCommand.Subcommands.First(c => c.Name == "verify");

        // Assert
        var signatureArg = verifyCommand.Arguments.FirstOrDefault(a => a.Name == "signature");
        signatureArg.Should().NotBeNull();
        signatureArg!.Arity.MinimumNumberOfValues.Should().Be(1);
    }

    [Fact]
    public void BuildRootCommand_InspectCommandHasRequiredFileArgument()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var inspectCommand = rootCommand.Subcommands.First(c => c.Name == "inspect");

        // Assert
        var fileArg = inspectCommand.Arguments.FirstOrDefault(a => a.Name == "file");
        fileArg.Should().NotBeNull();
        fileArg!.Arity.MinimumNumberOfValues.Should().Be(1);
    }

    [Fact]
    public void BuildRootCommand_AllCommandsHaveDescriptions()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        foreach (var command in rootCommand.Subcommands)
        {
            command.Description.Should().NotBeNullOrEmpty($"because command '{command.Name}' should have a description");
        }
    }

    [Fact]
    public void BuildRootCommand_CalledMultipleTimes_ReturnsNewInstances()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand1 = builder.BuildRootCommand();
        var rootCommand2 = builder.BuildRootCommand();

        // Assert
        rootCommand1.Should().NotBeSameAs(rootCommand2);
    }
}
