// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSignTool.Commands;

namespace CoseSignTool.Tests.Commands;

/// <summary>
/// Tests for the CommandBuilder class.
/// </summary>
[TestFixture]
public class CommandBuilderTests
{
    [Test]
    public void BuildRootCommand_ReturnsRootCommand()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        Assert.That(rootCommand, Is.Not.Null);
        Assert.That(rootCommand, Is.InstanceOf<RootCommand>());
    }

    [Test]
    public void BuildRootCommand_HasCorrectDescription()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        Assert.That(rootCommand.Description, Does.Contain("COSE Sign1"));
    }

    [Test]
    public void BuildRootCommand_HasSignEphemeralCommand()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var signCommand = rootCommand.Subcommands.FirstOrDefault(c => c.Name == "sign-ephemeral");
        Assert.That(signCommand, Is.Not.Null);
    }

    [Test]
    public void BuildRootCommand_HasVerifyCommand()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var verifyCommand = rootCommand.Subcommands.FirstOrDefault(c => c.Name == "verify");
        Assert.That(verifyCommand, Is.Not.Null);
    }

    [Test]
    public void BuildRootCommand_HasInspectCommand()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var inspectCommand = rootCommand.Subcommands.FirstOrDefault(c => c.Name == "inspect");
        Assert.That(inspectCommand, Is.Not.Null);
    }

    [Test]
    public void BuildRootCommand_SignEphemeralCommandHasOptionalPayloadArgument()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign-ephemeral");

        // Assert
        var payloadArg = signCommand.Arguments.FirstOrDefault(a => a.Name == "payload");
        Assert.That(payloadArg, Is.Not.Null);
        // Payload is optional to support stdin
        Assert.That(payloadArg!.Arity.MinimumNumberOfValues, Is.EqualTo(0));
        Assert.That(payloadArg!.Arity.MaximumNumberOfValues, Is.EqualTo(1));
    }

    [Test]
    public void BuildRootCommand_SignEphemeralCommandHasOutputOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign-ephemeral");

        // Assert
        var outputOption = signCommand.Options.FirstOrDefault(o => o.Name == "output");
        Assert.That(outputOption, Is.Not.Null);
    }

    [Test]
    public void BuildRootCommand_SignEphemeralCommandHasDetachedAliasForSignatureType()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign-ephemeral");

        // Assert
        var signatureTypeOption = signCommand.Options.FirstOrDefault(o => o.Name == "signature-type");
        Assert.That(signatureTypeOption, Is.Not.Null);
        // -d is now an alias for --signature-type
        Assert.That(signatureTypeOption!.Aliases, Does.Contain("-d"));
    }

    [Test]
    public void BuildRootCommand_VerifyCommandHasSignatureArgumentSupportingStdin()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var verifyCommand = rootCommand.Subcommands.First(c => c.Name == "verify");

        // Assert - signature is optional (MinimumNumberOfValues = 0) to support stdin
        var signatureArg = verifyCommand.Arguments.FirstOrDefault(a => a.Name == "signature");
        Assert.That(signatureArg, Is.Not.Null);
        Assert.That(signatureArg!.Arity.MinimumNumberOfValues, Is.EqualTo(0), "Signature should be optional to support stdin");
        Assert.That(signatureArg!.Arity.MaximumNumberOfValues, Is.EqualTo(1), "Should accept at most one argument");
    }

    [Test]
    public void BuildRootCommand_InspectCommandHasFileArgumentSupportingStdin()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var inspectCommand = rootCommand.Subcommands.First(c => c.Name == "inspect");

        // Assert - file is optional (MinimumNumberOfValues = 0) to support stdin
        var fileArg = inspectCommand.Arguments.FirstOrDefault(a => a.Name == "file");
        Assert.That(fileArg, Is.Not.Null);
        Assert.That(fileArg!.Arity.MinimumNumberOfValues, Is.EqualTo(0), "File should be optional to support stdin");
        Assert.That(fileArg!.Arity.MaximumNumberOfValues, Is.EqualTo(1), "Should accept at most one argument");
    }

    [Test]
    public void BuildRootCommand_AllCommandsHaveDescriptions()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        foreach (var command in rootCommand.Subcommands)
        {
            Assert.That(!string.IsNullOrEmpty(command.Description), $"Command '{command.Name}' should have a description");
        }
    }

    [Test]
    public void BuildRootCommand_CalledMultipleTimes_ReturnsNewInstances()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand1 = builder.BuildRootCommand();
        var rootCommand2 = builder.BuildRootCommand();

        // Assert
        Assert.That(rootCommand2, Is.Not.SameAs(rootCommand1));
    }

    [Test]
    public void BuildRootCommand_HasOutputFormatOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var outputFormatOption = rootCommand.Options.FirstOrDefault(o => o.Name == "output-format");
        Assert.That(outputFormatOption, Is.Not.Null);
    }

    [Test]
    public void BuildRootCommand_OutputFormatOptionHasAlias()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var outputFormatOption = rootCommand.Options.FirstOrDefault(o => o.Name == "output-format");
        Assert.That(outputFormatOption, Is.Not.Null);
        Assert.That(outputFormatOption!.Aliases, Does.Contain("-f"));
    }

    [Test]
    public void BuildRootCommand_HasVerboseOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();

        // Assert
        var verboseOption = rootCommand.Options.FirstOrDefault(o => o.Name == "verbose");
        Assert.That(verboseOption, Is.Not.Null);
    }

    [Test]
    public void BuildRootCommand_SignEphemeralCommandHasSignatureTypeOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign-ephemeral");

        // Assert
        var signatureTypeOption = signCommand.Options.FirstOrDefault(o => o.Name == "signature-type");
        Assert.That(signatureTypeOption, Is.Not.Null);
    }

    [Test]
    public void BuildRootCommand_SignEphemeralCommandHasContentTypeOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign-ephemeral");

        // Assert
        var contentTypeOption = signCommand.Options.FirstOrDefault(o => o.Name == "content-type");
        Assert.That(contentTypeOption, Is.Not.Null);
    }

    [Test]
    public void BuildRootCommand_SignEphemeralCommandHasQuietOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var signCommand = rootCommand.Subcommands.First(c => c.Name == "sign-ephemeral");

        // Assert
        var quietOption = signCommand.Options.FirstOrDefault(o => o.Name == "quiet");
        Assert.That(quietOption, Is.Not.Null);
    }

    [Test]
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
            Assert.That(rootCommand, Is.Not.Null);
            // Should still have the built-in commands
            Assert.That(rootCommand.Subcommands, Has.Some.Matches<System.CommandLine.Command>(c => c.Name == "sign-ephemeral"));
            Assert.That(rootCommand.Subcommands, Has.Some.Matches<System.CommandLine.Command>(c => c.Name == "verify"));
            Assert.That(rootCommand.Subcommands, Has.Some.Matches<System.CommandLine.Command>(c => c.Name == "inspect"));
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
    public void BuildRootCommand_WithNullPluginDirectories_DoesNotThrow()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand(null);

        // Assert
        Assert.That(rootCommand, Is.Not.Null);
    }

    [Test]
    public void BuildRootCommand_WithEmptyPluginDirectories_DoesNotThrow()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand([]);

        // Assert
        Assert.That(rootCommand, Is.Not.Null);
    }

    [Test]
    public void BuildRootCommand_VerifyCommandHasCorrectDescription()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var verifyCommand = rootCommand.Subcommands.First(c => c.Name == "verify");

        // Assert
        Assert.That(verifyCommand.Description, Does.Contain("Verify"));
    }

    [Test]
    public void BuildRootCommand_InspectCommandHasCorrectDescription()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var inspectCommand = rootCommand.Subcommands.First(c => c.Name == "inspect");

        // Assert
        Assert.That(inspectCommand.Description, Does.Contain("Inspect"));
    }

    [Test]
    public void BuildRootCommand_VerifyCommandHasPayloadOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var verifyCommand = rootCommand.Subcommands.First(c => c.Name == "verify");

        // Assert
        var payloadOption = verifyCommand.Options.FirstOrDefault(o => o.Name == "payload");
        Assert.That(payloadOption, Is.Not.Null, "Verify command should have --payload option");
        Assert.That(payloadOption!.Aliases, Does.Contain("-p"), "Should have -p alias");
    }

    [Test]
    public void BuildRootCommand_VerifyCommandHasSignatureOnlyOption()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var verifyCommand = rootCommand.Subcommands.First(c => c.Name == "verify");

        // Assert
        var signatureOnlyOption = verifyCommand.Options.FirstOrDefault(o => o.Name == "signature-only");
        Assert.That(signatureOnlyOption, Is.Not.Null, "Verify command should have --signature-only option");
    }

    [Test]
    public void BuildRootCommand_VerifyDescription_ContainsPayloadExamples()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var verifyCommand = rootCommand.Subcommands.First(c => c.Name == "verify");

        // Assert
        Assert.That(verifyCommand.Description, Does.Contain("--payload"), "Description should include --payload example");
    }

    [Test]
    public void BuildRootCommand_VerifyDescription_ContainsSignatureOnlyExamples()
    {
        // Arrange
        var builder = new CommandBuilder();

        // Act
        var rootCommand = builder.BuildRootCommand();
        var verifyCommand = rootCommand.Subcommands.First(c => c.Name == "verify");

        // Assert
        Assert.That(verifyCommand.Description, Does.Contain("--signature-only"), "Description should include --signature-only example");
    }
}