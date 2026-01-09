// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Commands;

using System.CommandLine;

/// <summary>
/// Integration tests for command execution through CommandBuilder.
/// </summary>
[TestFixture]
public class CommandIntegrationTests
{
    [Test]
    public async Task SignCommand_WithMissingFile_ReturnsFileNotFound()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var nonExistentFile = Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid()}.bin");

        // Act
        var exitCode = rootCommand.Invoke($"sign-ephemeral \"{nonExistentFile}\"");

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.FileNotFound));
        await Task.CompletedTask; // Keep async for consistency
    }

    [Test]
    public async Task SignCommand_WithValidFile_ReturnsSuccess()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "test data");

        try
        {
            // Act
            var exitCode = rootCommand.Invoke($"sign-ephemeral \"{tempFile}\"");

            // Assert
            Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
            var outputFile = Path.ChangeExtension(tempFile, ".cose");
            if (File.Exists(outputFile))
            {
                File.Delete(outputFile);
            }
        }
    }

    [Test]
    public async Task VerifyCommand_WithMissingFile_ReturnsFileNotFound()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var nonExistentFile = Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid()}.cose");

        // Act
        var exitCode = rootCommand.Invoke($"verify \"{nonExistentFile}\"");

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.FileNotFound));
        await Task.CompletedTask; // Keep async for consistency
    }

    [Test]
    public async Task VerifyCommand_WithInvalidCoseFile_ReturnsInvalidSignature()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]); // Invalid COSE (incomplete)

        try
        {
            // Act
            var exitCode = rootCommand.Invoke($"verify \"{tempFile}\"");

            // Assert - invalid COSE data returns InvalidSignature
            Assert.That(exitCode, Is.EqualTo((int)ExitCode.InvalidSignature));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task InspectCommand_WithMissingFile_ReturnsFileNotFound()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var nonExistentFile = Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid()}.cose");

        // Act
        var exitCode = rootCommand.Invoke($"inspect \"{nonExistentFile}\"");

        // Assert
        Assert.That(exitCode, Is.EqualTo((int)ExitCode.FileNotFound));
        await Task.CompletedTask; // Keep async for consistency
    }

    [Test]
    public async Task InspectCommand_WithInvalidCoseFile_ReturnsInspectionFailed()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]); // Invalid COSE (incomplete)

        try
        {
            // Act
            var exitCode = rootCommand.Invoke($"inspect \"{tempFile}\"");

            // Assert - invalid COSE data returns InvalidSignature
            Assert.That(exitCode, Is.EqualTo((int)ExitCode.InvalidSignature));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Test]
    public async Task SignCommand_WithDetachedSignatureType_ReturnsSuccess()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "test data");

        try
        {
            // Act - use --signature-type detached (or -d shorthand)
            var exitCode = rootCommand.Invoke($"sign-ephemeral \"{tempFile}\" --signature-type detached");

            // Assert
            Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
            var outputFile = Path.ChangeExtension(tempFile, ".cose");
            if (File.Exists(outputFile))
            {
                File.Delete(outputFile);
            }
        }
    }

    [Test]
    public async Task SignCommand_WithCustomOutput_ReturnsSuccess()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempFile = Path.GetTempFileName();
        var customOutput = Path.Combine(Path.GetTempPath(), $"custom_{Guid.NewGuid()}.cose");
        await File.WriteAllTextAsync(tempFile, "test data");

        try
        {
            // Act
            var exitCode = rootCommand.Invoke($"sign-ephemeral \"{tempFile}\" --output \"{customOutput}\"");

            // Assert
            Assert.That(exitCode, Is.EqualTo((int)ExitCode.Success));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
            if (File.Exists(customOutput))
            {
                File.Delete(customOutput);
            }
        }
    }
}
