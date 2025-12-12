// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Commands.Handlers;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;

namespace CoseSignTool.Tests.Commands.Handlers;

/// <summary>
/// Tests for the InspectCommandHandler class.
/// </summary>
public class InspectCommandHandlerTests
{
    [Fact]
    public async Task HandleAsync_WithNullFile_ReturnsFileNotFound()
    {
        // Arrange
        var handler = new InspectCommandHandler();
        var context = CreateInvocationContext(file: null);

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        result.Should().Be((int)ExitCode.FileNotFound);
    }

    [Fact]
    public async Task HandleAsync_WithNonExistentFile_ReturnsFileNotFound()
    {
        // Arrange
        var handler = new InspectCommandHandler();
        var nonExistentFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.cose"));
        var context = CreateInvocationContext(file: nonExistentFile);

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        result.Should().Be((int)ExitCode.FileNotFound);
    }

    [Fact]
    public async Task HandleAsync_WithValidFile_ReturnsSuccess()
    {
        // Arrange
        var handler = new InspectCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84, 0x43, 0xA1]); // Dummy COSE bytes
        var file = new FileInfo(tempFile);
        var context = CreateInvocationContext(file: file);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - stub implementation returns success
            result.Should().Be((int)ExitCode.Success);
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
    public void HandleAsync_WithNullContext_ThrowsArgumentNullException()
    {
        // Arrange
        var handler = new InspectCommandHandler();

        // Act
        Func<Task> act = async () => await handler.HandleAsync(null!);

        // Assert
        act.Should().ThrowAsync<ArgumentNullException>();
    }

    private static InvocationContext CreateInvocationContext(FileInfo? file = null)
    {
        var command = new Command("inspect");
        var fileArg = new Argument<FileInfo?>("file");
        
        command.AddArgument(fileArg);

        var args = file != null ? $"inspect \"{file.FullName}\"" : "inspect";
        var parseResult = command.Parse(args);
        return new InvocationContext(parseResult);
    }
}
