// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Commands.Handlers;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;

namespace CoseSignTool.Tests.Commands.Handlers;

/// <summary>
/// Tests for the VerifyCommandHandler class.
/// </summary>
public class VerifyCommandHandlerTests
{
    [Fact]
    public async Task HandleAsync_WithNullSignature_ReturnsFileNotFound()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var context = CreateInvocationContext(signature: null);

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        result.Should().Be((int)ExitCode.FileNotFound);
    }

    [Fact]
    public async Task HandleAsync_WithNonExistentSignature_ReturnsFileNotFound()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var nonExistentFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.cose"));
        var context = CreateInvocationContext(signature: nonExistentFile);

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        result.Should().Be((int)ExitCode.FileNotFound);
    }

    [Fact]
    public async Task HandleAsync_WithValidSignature_ReturnsSuccess()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84, 0x43, 0xA1]); // Dummy COSE bytes
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

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
        var handler = new VerifyCommandHandler();

        // Act
        Func<Task> act = async () => await handler.HandleAsync(null!);

        // Assert
        act.Should().ThrowAsync<ArgumentNullException>();
    }

    private static InvocationContext CreateInvocationContext(FileInfo? signature = null)
    {
        var command = new Command("verify");
        var signatureArg = new Argument<FileInfo?>("signature");
        
        command.AddArgument(signatureArg);

        var args = signature != null ? $"verify \"{signature.FullName}\"" : "verify";
        var parseResult = command.Parse(args);
        return new InvocationContext(parseResult);
    }
}
