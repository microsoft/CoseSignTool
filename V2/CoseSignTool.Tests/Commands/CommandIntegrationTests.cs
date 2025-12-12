// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Commands;
using System.CommandLine;

namespace CoseSignTool.Tests.Commands;

/// <summary>
/// Integration tests for command execution through CommandBuilder.
/// </summary>
public class CommandIntegrationTests
{
    [Fact]
    public async Task SignCommand_WithMissingFile_ReturnsFileNotFound()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var nonExistentFile = Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid()}.bin");

        // Act
        var exitCode = rootCommand.Invoke($"sign-ephemeral \"{nonExistentFile}\"");

        // Assert
        Assert.Equal((int)ExitCode.FileNotFound, exitCode);
        await Task.CompletedTask; // Keep async for consistency
    }

    [Fact]
    public async Task SignCommand_WithValidFile_ReturnsSuccess()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "test data");

        try
        {
            // Act
            var exitCode = rootCommand.Invoke($"sign-ephemeral \"{tempFile}\"");

            // Assert
            Assert.Equal((int)ExitCode.Success, exitCode);
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

    [Fact]
    public async Task VerifyCommand_WithMissingFile_ReturnsFileNotFound()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var nonExistentFile = Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid()}.cose");

        // Act
        var exitCode = rootCommand.Invoke($"verify \"{nonExistentFile}\"");

        // Assert
        Assert.Equal((int)ExitCode.FileNotFound, exitCode);
        await Task.CompletedTask; // Keep async for consistency
    }

    [Fact]
    public async Task VerifyCommand_WithInvalidCoseFile_ReturnsInvalidSignature()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]); // Invalid COSE (incomplete)

        try
        {
            // Act
            var exitCode = rootCommand.Invoke($"verify \"{tempFile}\"");

            // Assert - invalid COSE data returns InvalidSignature
            Assert.Equal((int)ExitCode.InvalidSignature, exitCode);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public async Task InspectCommand_WithMissingFile_ReturnsFileNotFound()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var nonExistentFile = Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid()}.cose");

        // Act
        var exitCode = rootCommand.Invoke($"inspect \"{nonExistentFile}\"");

        // Assert
        Assert.Equal((int)ExitCode.FileNotFound, exitCode);
        await Task.CompletedTask; // Keep async for consistency
    }

    [Fact]
    public async Task InspectCommand_WithInvalidCoseFile_ReturnsInspectionFailed()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]); // Invalid COSE (incomplete)

        try
        {
            // Act
            var exitCode = rootCommand.Invoke($"inspect \"{tempFile}\"");

            // Assert - invalid COSE data returns InspectionFailed
            Assert.Equal((int)ExitCode.InspectionFailed, exitCode);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    [Fact]
    public async Task SignCommand_WithDetachedOption_ReturnsSuccess()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "test data");

        try
        {
            // Act
            var exitCode = rootCommand.Invoke($"sign-ephemeral \"{tempFile}\" --detached");

            // Assert
            Assert.Equal((int)ExitCode.Success, exitCode);
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

    [Fact]
    public async Task SignCommand_WithCustomOutput_ReturnsSuccess()
    {
        // Arrange
        var builder = new CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempFile = Path.GetTempFileName();
        var customOutput = Path.Combine(Path.GetTempPath(), $"custom_{Guid.NewGuid()}.cose");
        await File.WriteAllTextAsync(tempFile, "test data");

        try
        {
            // Act
            var exitCode = rootCommand.Invoke($"sign-ephemeral \"{tempFile}\" --output \"{customOutput}\"");

            // Assert
            Assert.Equal((int)ExitCode.Success, exitCode);
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
