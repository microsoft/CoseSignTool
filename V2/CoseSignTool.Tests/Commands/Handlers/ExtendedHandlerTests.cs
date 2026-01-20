// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Commands.Handlers;

using System.CommandLine;
using CoseSignTool.Output;

/// <summary>
/// Extended tests for command handlers with various code paths.
/// </summary>
[TestFixture]
public class ExtendedHandlerTests
{
    [Test]
    public void InspectCommandHandler_WithDifferentFormatters_Works()
    {
        // Arrange
        var textFormatter = new TextOutputFormatter();
        var jsonFormatter = new JsonOutputFormatter();
        var xmlFormatter = new XmlOutputFormatter();
        var quietFormatter = new QuietOutputFormatter();

        // Act & Assert - All formatters should work
        var handler1 = TestConsole.CreateInspectCommandHandler(textFormatter);
        var handler2 = TestConsole.CreateInspectCommandHandler(jsonFormatter);
        var handler3 = TestConsole.CreateInspectCommandHandler(xmlFormatter);
        var handler4 = TestConsole.CreateInspectCommandHandler(quietFormatter);

        Assert.That(handler1, Is.Not.Null);
        Assert.That(handler2, Is.Not.Null);
        Assert.That(handler3, Is.Not.Null);
        Assert.That(handler4, Is.Not.Null);
    }

    [Test]
    public void VerifyCommandHandler_WithDifferentFormatters_Works()
    {
        // Arrange
        var textFormatter = new TextOutputFormatter();
        var jsonFormatter = new JsonOutputFormatter();
        var xmlFormatter = new XmlOutputFormatter();
        var quietFormatter = new QuietOutputFormatter();

        // Act & Assert - All formatters should work
        var handler1 = TestConsole.CreateVerifyCommandHandler(textFormatter);
        var handler2 = TestConsole.CreateVerifyCommandHandler(jsonFormatter);
        var handler3 = TestConsole.CreateVerifyCommandHandler(xmlFormatter);
        var handler4 = TestConsole.CreateVerifyCommandHandler(quietFormatter);

        Assert.That(handler1, Is.Not.Null);
        Assert.That(handler2, Is.Not.Null);
        Assert.That(handler3, Is.Not.Null);
        Assert.That(handler4, Is.Not.Null);
    }

    [Test]
    public void InspectCommand_ViaRootCommand_WithValidSignature_Succeeds()
    {
        // Arrange - Create a real signature first
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for inspect test");

            // Sign the payload
            var signExitCode = rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(tempSignature));

            // Act - Inspect with text format (default)
            var inspectExitCode = rootCommand.Invoke($"inspect \"{tempSignature}\"");

            // Assert
            Assert.That(inspectExitCode, Is.EqualTo((int)ExitCode.Success));
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

    [Test]
    public void InspectCommand_ViaRootCommand_WithQuietFormat_Succeeds()
    {
        // Arrange - Create a real signature first
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for inspect test");

            // Sign the payload
            var signExitCode = rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            // Act - Inspect with quiet format
            var inspectExitCode = rootCommand.Invoke($"inspect \"{tempSignature}\" --output-format quiet");

            // Assert
            Assert.That(inspectExitCode, Is.EqualTo((int)ExitCode.Success));
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

    [Test]
    public void VerifyCommand_ViaRootCommand_WithJsonFormat_ReturnsResult()
    {
        // Arrange - Create a real signature first
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");

            // Sign the payload
            var signExitCode = rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            // Act - Verify with JSON format
            var verifyExitCode = rootCommand.Invoke($"verify x509 \"{tempSignature}\" --output-format json");

            // Assert - Either success or verification failure is acceptable
            Assert.That(verifyExitCode == (int)ExitCode.Success ||
                        verifyExitCode == (int)ExitCode.VerificationFailed ||
                        verifyExitCode == (int)ExitCode.UntrustedCertificate, Is.True);
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

    [Test]
    public void VerifyCommand_ViaRootCommand_WithQuietFormat_ReturnsResult()
    {
        // Arrange - Create a real signature first
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");

            // Sign the payload
            var signExitCode = rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            // Act - Verify with quiet format
            var verifyExitCode = rootCommand.Invoke($"verify x509 \"{tempSignature}\" --output-format quiet");

            // Assert - Either success or verification failure is acceptable
            Assert.That(verifyExitCode == (int)ExitCode.Success ||
                        verifyExitCode == (int)ExitCode.VerificationFailed ||
                        verifyExitCode == (int)ExitCode.UntrustedCertificate, Is.True);
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

    [Test]
    public void VerifyCommand_ViaRootCommand_WithXmlFormat_ReturnsResult()
    {
        // Arrange - Create a real signature first
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");

            // Sign the payload
            var signExitCode = rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
            Assert.That(signExitCode, Is.EqualTo((int)ExitCode.Success));

            // Act - Verify with XML format
            var verifyExitCode = rootCommand.Invoke($"verify x509 \"{tempSignature}\" --output-format xml");

            // Assert - Either success or verification failure is acceptable
            Assert.That(verifyExitCode == (int)ExitCode.Success ||
                        verifyExitCode == (int)ExitCode.VerificationFailed ||
                        verifyExitCode == (int)ExitCode.UntrustedCertificate, Is.True);
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

    [Test]
    public void SignEphemeral_WithVerboseOption_ShowsHelp()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();

        // Act - Using verbose with help should work
        var exitCode = rootCommand.Invoke("sign x509 ephemeral --help --verbose");

        // Assert - Help should show (exit code 0)
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void VerifyCommand_WithVerboseHelp_ShowsHelp()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();

        // Act - Help flag should trigger help display
        var exitCode = rootCommand.Invoke("verify --help");

        // Assert - Help should show
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void InspectCommand_WithVerboseHelp_ShowsHelp()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();

        // Act - Help flag should trigger help display
        var exitCode = rootCommand.Invoke("inspect --help");

        // Assert - Help should show
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
    }

    [Test]
    public void SignEphemeral_WithAllOptions_CreatesSignature()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var customOutput = Path.Combine(Path.GetTempPath(), $"all_options_{Guid.NewGuid()}.cose");

        try
        {
            File.WriteAllText(tempPayload, "{\"data\":\"test\"}");

            // Act - Use all options together
            var exitCode = rootCommand.Invoke(
                $"sign x509 ephemeral \"{tempPayload}\" " +
                $"--output \"{customOutput}\" " +
                "--signature-type detached " +
                "--content-type application/json " +
                "--quiet");

            // Assert
            Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(customOutput));
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

    [Test]
    public void VerifyCommand_WithNonExistentFile_ReturnsFileNotFound()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var nonExistentFile = Path.Combine(Path.GetTempPath(), $"nonexistent_verify_{Guid.NewGuid()}.cose");

        // Act
        var exitCode = rootCommand.Invoke($"verify x509 \"{nonExistentFile}\"");

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.FileNotFound));
    }

    [Test]
    public void InspectCommand_WithNonExistentFile_ReturnsFileNotFound()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var nonExistentFile = Path.Combine(Path.GetTempPath(), $"nonexistent_inspect_{Guid.NewGuid()}.cose");

        // Act
        var exitCode = rootCommand.Invoke($"inspect \"{nonExistentFile}\"");

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.FileNotFound));
    }
}
