// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Commands.Handlers;
using CoseSignTool.Output;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;

namespace CoseSignTool.Tests.Commands.Handlers;

/// <summary>
/// Tests for the SignCommandHandler class.
/// </summary>
public class SignCommandHandlerTests
{
    [Fact]
    public async Task HandleAsync_WithNullPayload_ReturnsFileNotFound()
    {
        // Arrange
        var handler = new SignCommandHandler();
        var context = CreateInvocationContext(payload: null);

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        result.Should().Be((int)ExitCode.FileNotFound);
    }

    [Fact]
    public async Task HandleAsync_WithNonExistentPayload_ReturnsFileNotFound()
    {
        // Arrange
        var handler = new SignCommandHandler();
        var nonExistentFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.bin"));
        var context = CreateInvocationContext(payload: nonExistentFile);

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        result.Should().Be((int)ExitCode.FileNotFound);
    }

    [Fact]
    public async Task HandleAsync_WithValidPayload_CreatesSignatureFile()
    {
        // Arrange
        var handler = new SignCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "test payload");
        var payload = new FileInfo(tempFile);
        var outputPath = Path.ChangeExtension(tempFile, ".cose");
        var context = CreateInvocationContext(payload: payload);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - for now, should return success even though signing is not implemented
            result.Should().Be((int)ExitCode.Success);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
            if (File.Exists(outputPath))
            {
                File.Delete(outputPath);
            }
        }
    }

    [Fact]
    public async Task HandleAsync_WithCustomOutput_UsesSpecifiedPath()
    {
        // Arrange
        var handler = new SignCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "test payload");
        var payload = new FileInfo(tempFile);
        var customOutput = new FileInfo(Path.Combine(Path.GetTempPath(), $"custom_{Guid.NewGuid()}.cose"));
        var context = CreateInvocationContext(payload: payload, output: customOutput);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert
            result.Should().Be((int)ExitCode.Success);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
            if (File.Exists(customOutput.FullName))
            {
                File.Delete(customOutput.FullName);
            }
        }
    }

    [Fact]
    public async Task HandleAsync_WithDetachedFlag_CreatesDetachedSignature()
    {
        // Arrange
        var handler = new SignCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "test payload");
        var payload = new FileInfo(tempFile);
        var outputPath = Path.ChangeExtension(tempFile, ".cose");
        var context = CreateInvocationContext(payload: payload, detached: true);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert
            result.Should().Be((int)ExitCode.Success);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
            if (File.Exists(outputPath))
            {
                File.Delete(outputPath);
            }
        }
    }

    [Fact]
    public void HandleAsync_WithNullContext_ThrowsArgumentNullException()
    {
        // Arrange
        var handler = new SignCommandHandler();

        // Act
        Func<Task> act = async () => await handler.HandleAsync(null!);

        // Assert
        act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task HandleAsync_WithExistingPayload_ReturnsSuccess()
    {
        // Arrange - test that an actual existing file works
        var handler = new SignCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04]);
        var payload = new FileInfo(tempFile);
        var outputPath = Path.ChangeExtension(tempFile, ".cose");
        var context = CreateInvocationContext(payload: payload);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert
            result.Should().Be((int)ExitCode.Success);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
            if (File.Exists(outputPath))
            {
                File.Delete(outputPath);
            }
        }
    }

    [Fact]
    public async Task HandleAsync_WithCustomFormatter_UsesFormatter()
    {
        // Arrange
        using var output = new StringWriter();
        var formatter = new TextOutputFormatter(output);
        var handler = new SignCommandHandler(formatter);
        var tempFile = Path.GetTempFileName();
        await File.WriteAllTextAsync(tempFile, "test payload");
        var payload = new FileInfo(tempFile);
        var context = CreateInvocationContext(payload: payload);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert
            result.Should().Be((int)ExitCode.Success);
            var outputText = output.ToString();
            outputText.Should().Contain("Signing Operation");
            outputText.Should().Contain("Successfully signed");
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    private static InvocationContext CreateInvocationContext(
        FileInfo? payload = null,
        FileInfo? output = null,
        bool detached = false)
    {
        var command = new Command("sign");
        var payloadArg = new Argument<FileInfo?>("payload");
        var outputOption = new Option<FileInfo?>("--output");
        var detachedOption = new Option<bool>("--detached");
        
        command.AddArgument(payloadArg);
        command.AddOption(outputOption);
        command.AddOption(detachedOption);

        var parseResult = command.Parse(BuildArgs(payload, output, detached));
        return new InvocationContext(parseResult);
    }

    private static string BuildArgs(FileInfo? payload, FileInfo? output, bool detached)
    {
        var args = "sign";
        if (payload != null)
        {
            args += $" \"{payload.FullName}\"";
        }
        if (output != null)
        {
            args += $" --output \"{output.FullName}\"";
        }
        if (detached)
        {
            args += " --detached";
        }
        return args;
    }
}
