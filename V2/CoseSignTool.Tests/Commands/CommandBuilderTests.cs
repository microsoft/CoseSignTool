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
        Assert.NotNull(rootCommand);
        Assert.IsType<RootCommand>(rootCommand);
    }

    [Fact]
    public void BuildRootCommand_HasCorrectDescription()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        Assert.Contains("COSE Sign1", rootCommand.Description);
    }

    [Fact]
    public void BuildRootCommand_HasSignEphemeralCommand()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var signCommand = rootCommand.Subcommands.FirstOrDefault(c => c.Name == "sign-ephemeral");
        Assert.NotNull(signCommand);
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
        Assert.NotNull(verifyCommand);
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
        Assert.NotNull(inspectCommand);
    }

    [Fact]
    public void BuildRootCommand_SignEphemeralCommandHasOptionalPayloadArgument()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign-ephemeral");

        // Assert
        var payloadArg = signCommand.Arguments.FirstOrDefault(a => a.Name == "payload");
        Assert.NotNull(payloadArg);
        // Payload is optional to support stdin
        Assert.Equal(0, payloadArg!.Arity.MinimumNumberOfValues);
        Assert.Equal(1, payloadArg!.Arity.MaximumNumberOfValues);
    }

    [Fact]
    public void BuildRootCommand_SignEphemeralCommandHasOutputOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign-ephemeral");

        // Assert
        var outputOption = signCommand.Options.FirstOrDefault(o => o.Name == "output");
        Assert.NotNull(outputOption);
    }

    [Fact]
    public void BuildRootCommand_SignEphemeralCommandHasDetachedOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign-ephemeral");

        // Assert
        var detachedOption = signCommand.Options.FirstOrDefault(o => o.Name == "detached");
        Assert.NotNull(detachedOption);
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
        Assert.NotNull(signatureArg);
        Assert.Equal(1, signatureArg!.Arity.MinimumNumberOfValues);
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
        Assert.NotNull(fileArg);
        Assert.Equal(1, fileArg!.Arity.MinimumNumberOfValues);
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
            Assert.False(string.IsNullOrEmpty(command.Description), $"Command '{command.Name}' should have a description");
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
        Assert.NotSame(rootCommand2, rootCommand1);
    }

    [Fact]
    public void BuildRootCommand_HasOutputFormatOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var outputFormatOption = rootCommand.Options.FirstOrDefault(o => o.Name == "output-format");
        Assert.NotNull(outputFormatOption);
    }

    [Fact]
    public void BuildRootCommand_OutputFormatOptionHasAlias()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var outputFormatOption = rootCommand.Options.FirstOrDefault(o => o.Name == "output-format");
        Assert.NotNull(outputFormatOption);
        Assert.Contains("-f", outputFormatOption!.Aliases);
    }

    [Fact]
    public void BuildRootCommand_HasVerboseOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var verboseOption = rootCommand.Options.FirstOrDefault(o => o.Name == "verbose");
        Assert.NotNull(verboseOption);
    }

    [Fact]
    public void BuildRootCommand_SignEphemeralCommandHasSignatureTypeOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign-ephemeral");

        // Assert
        var signatureTypeOption = signCommand.Options.FirstOrDefault(o => o.Name == "signature-type");
        Assert.NotNull(signatureTypeOption);
    }

    [Fact]
    public void BuildRootCommand_SignEphemeralCommandHasContentTypeOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign-ephemeral");

        // Assert
        var contentTypeOption = signCommand.Options.FirstOrDefault(o => o.Name == "content-type");
        Assert.NotNull(contentTypeOption);
    }

    [Fact]
    public void BuildRootCommand_SignEphemeralCommandHasQuietOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign-ephemeral");

        // Assert
        var quietOption = signCommand.Options.FirstOrDefault(o => o.Name == "quiet");
        Assert.NotNull(quietOption);
    }

    [Fact]
    public void BuildRootCommand_WithAdditionalPluginDirectories_DoesNotThrow()
    {
        // Arrange
        var builder = new CommandBuilder();
        var tempDir = Path.Combine(Path.GetTempPath(), $"plugins_test_{Guid.NewGuid()}");
        Directory.CreateDirectory(tempDir);

        try
        {
            // Act
            var rootCommand = builder.BuildRootCommand([tempDir]);

            // Assert
            Assert.NotNull(rootCommand);
            // Should still have the built-in commands
            Assert.Contains(rootCommand.Subcommands, c => c.Name == "sign-ephemeral");
            Assert.Contains(rootCommand.Subcommands, c => c.Name == "verify");
            Assert.Contains(rootCommand.Subcommands, c => c.Name == "inspect");
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public void BuildRootCommand_WithNullPluginDirectories_DoesNotThrow()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand(null);

        // Assert
        Assert.NotNull(rootCommand);
    }

    [Fact]
    public void BuildRootCommand_WithEmptyPluginDirectories_DoesNotThrow()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand([]);

        // Assert
        Assert.NotNull(rootCommand);
    }

    [Fact]
    public void BuildRootCommand_VerifyCommandHasCorrectDescription()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var verifyCommand = rootCommand.Subcommands.First(c => c.Name == "verify");

        // Assert
        Assert.Contains("Verify", verifyCommand.Description);
    }

    [Fact]
    public void BuildRootCommand_InspectCommandHasCorrectDescription()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var inspectCommand = rootCommand.Subcommands.First(c => c.Name == "inspect");

        // Assert
        Assert.Contains("Inspect", inspectCommand.Description);
    }
}
