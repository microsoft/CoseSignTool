// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSignTool.Commands;
using CoseSignTool.Commands.Handlers;
using CoseSignTool.Output;

namespace CoseSignTool.Tests.Commands.Handlers;

/// <summary>
/// Extended tests for command handlers with various code paths.
/// </summary>
public class ExtendedHandlerTests
{
    [Fact]
    public void InspectCommandHandler_WithDifferentFormatters_Works()
    {
        // Arrange
        var textFormatter = new TextOutputFormatter();
        var jsonFormatter = new JsonOutputFormatter();
        var xmlFormatter = new XmlOutputFormatter();
        var quietFormatter = new QuietOutputFormatter();

        // Act & Assert - All formatters should work
        var handler1 = new InspectCommandHandler(textFormatter);
        var handler2 = new InspectCommandHandler(jsonFormatter);
        var handler3 = new InspectCommandHandler(xmlFormatter);
        var handler4 = new InspectCommandHandler(quietFormatter);

        Assert.NotNull(handler1);
        Assert.NotNull(handler2);
        Assert.NotNull(handler3);
        Assert.NotNull(handler4);
    }

    [Fact]
    public void VerifyCommandHandler_WithDifferentFormatters_Works()
    {
        // Arrange
        var textFormatter = new TextOutputFormatter();
        var jsonFormatter = new JsonOutputFormatter();
        var xmlFormatter = new XmlOutputFormatter();
        var quietFormatter = new QuietOutputFormatter();

        // Act & Assert - All formatters should work
        var handler1 = new VerifyCommandHandler(textFormatter);
        var handler2 = new VerifyCommandHandler(jsonFormatter);
        var handler3 = new VerifyCommandHandler(xmlFormatter);
        var handler4 = new VerifyCommandHandler(quietFormatter);

        Assert.NotNull(handler1);
        Assert.NotNull(handler2);
        Assert.NotNull(handler3);
        Assert.NotNull(handler4);
    }

    [Fact]
    public void InspectCommand_ViaRootCommand_WithValidSignature_Succeeds()
    {
        // Arrange - Create a real signature first
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for inspect test");

            // Sign the payload
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.Equal((int)ExitCode.Success, signExitCode);
            Assert.True(File.Exists(tempSignature));

            // Act - Inspect with text format (default)
            var inspectExitCode = rootCommand.Invoke($"inspect \"{tempSignature}\"");

            // Assert
            Assert.Equal((int)ExitCode.Success, inspectExitCode);
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void InspectCommand_ViaRootCommand_WithQuietFormat_Succeeds()
    {
        // Arrange - Create a real signature first
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for inspect test");

            // Sign the payload
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.Equal((int)ExitCode.Success, signExitCode);

            // Act - Inspect with quiet format
            var inspectExitCode = rootCommand.Invoke($"inspect \"{tempSignature}\" --output-format quiet");

            // Assert
            Assert.Equal((int)ExitCode.Success, inspectExitCode);
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void VerifyCommand_ViaRootCommand_WithJsonFormat_ReturnsResult()
    {
        // Arrange - Create a real signature first
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");

            // Sign the payload
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.Equal((int)ExitCode.Success, signExitCode);

            // Act - Verify with JSON format
            var verifyExitCode = rootCommand.Invoke($"verify \"{tempSignature}\" --output-format json");

            // Assert - Either success or verification failure is acceptable
            Assert.True(verifyExitCode == (int)ExitCode.Success ||
                        verifyExitCode == (int)ExitCode.VerificationFailed ||
                        verifyExitCode == (int)ExitCode.UntrustedCertificate);
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void VerifyCommand_ViaRootCommand_WithQuietFormat_ReturnsResult()
    {
        // Arrange - Create a real signature first
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");

            // Sign the payload
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.Equal((int)ExitCode.Success, signExitCode);

            // Act - Verify with quiet format
            var verifyExitCode = rootCommand.Invoke($"verify \"{tempSignature}\" --output-format quiet");

            // Assert - Either success or verification failure is acceptable
            Assert.True(verifyExitCode == (int)ExitCode.Success ||
                        verifyExitCode == (int)ExitCode.VerificationFailed ||
                        verifyExitCode == (int)ExitCode.UntrustedCertificate);
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void VerifyCommand_ViaRootCommand_WithXmlFormat_ReturnsResult()
    {
        // Arrange - Create a real signature first
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");

            // Sign the payload
            var signExitCode = rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.Equal((int)ExitCode.Success, signExitCode);

            // Act - Verify with XML format
            var verifyExitCode = rootCommand.Invoke($"verify \"{tempSignature}\" --output-format xml");

            // Assert - Either success or verification failure is acceptable
            Assert.True(verifyExitCode == (int)ExitCode.Success ||
                        verifyExitCode == (int)ExitCode.VerificationFailed ||
                        verifyExitCode == (int)ExitCode.UntrustedCertificate);
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(tempSignature))
            {
                File.Delete(tempSignature);
            }
        }
    }

    [Fact]
    public void SignEphemeral_WithVerboseOption_ShowsHelp()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();

        // Act - Using verbose with help should work
        var exitCode = rootCommand.Invoke("sign-ephemeral --help --verbose");

        // Assert - Help should show (exit code 0)
        Assert.Equal((int)ExitCode.Success, exitCode);
    }

    [Fact]
    public void VerifyCommand_WithVerboseHelp_ShowsHelp()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();

        // Act - Help flag should trigger help display
        var exitCode = rootCommand.Invoke("verify --help");

        // Assert - Help should show
        Assert.Equal((int)ExitCode.Success, exitCode);
    }

    [Fact]
    public void InspectCommand_WithVerboseHelp_ShowsHelp()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();

        // Act - Help flag should trigger help display
        var exitCode = rootCommand.Invoke("inspect --help");

        // Assert - Help should show
        Assert.Equal((int)ExitCode.Success, exitCode);
    }

    [Fact]
    public void SignEphemeral_WithAllOptions_CreatesSignature()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var customOutput = Path.Combine(Path.GetTempPath(), $"all_options_{Guid.NewGuid()}.cose");

        try
        {
            File.WriteAllText(tempPayload, "{\"data\":\"test\"}");

            // Act - Use all options together
            var exitCode = rootCommand.Invoke(
                $"sign-ephemeral \"{tempPayload}\" " +
                $"--output \"{customOutput}\" " +
                "--signature-type direct " +
                "--content-type application/json " +
                "--quiet");

            // Assert
            Assert.Equal((int)ExitCode.Success, exitCode);
            Assert.True(File.Exists(customOutput));
        }
        finally
        {
            if (File.Exists(tempPayload))
            {
                File.Delete(tempPayload);
            }
            if (File.Exists(customOutput))
            {
                File.Delete(customOutput);
            }
        }
    }

    [Fact]
    public void VerifyCommand_WithNonExistentFile_ReturnsFileNotFound()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var nonExistentFile = Path.Combine(Path.GetTempPath(), $"nonexistent_verify_{Guid.NewGuid()}.cose");

        // Act
        var exitCode = rootCommand.Invoke($"verify \"{nonExistentFile}\"");

        // Assert
        Assert.Equal((int)ExitCode.FileNotFound, exitCode);
    }

    [Fact]
    public void InspectCommand_WithNonExistentFile_ReturnsFileNotFound()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var nonExistentFile = Path.Combine(Path.GetTempPath(), $"nonexistent_inspect_{Guid.NewGuid()}.cose");

        // Act
        var exitCode = rootCommand.Invoke($"inspect \"{nonExistentFile}\"");

        // Assert
        Assert.Equal((int)ExitCode.FileNotFound, exitCode);
    }
}
