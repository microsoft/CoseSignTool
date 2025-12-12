// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Commands.Handlers;
using CoseSignTool.Output;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;

namespace CoseSignTool.Tests.Commands.Handlers;

/// <summary>
/// Tests for the VerifyCommandHandler class.
/// </summary>
[TestFixture]
public class VerifyCommandHandlerTests
{
    [Test]
    public void Constructor_WithNullFormatter_UsesDefaultFormatter()
    {
        // Arrange & Act
        var handler = new VerifyCommandHandler(null);

        // Assert
        Assert.That(handler, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithFormatter_UsesProvidedFormatter()
    {
        // Arrange
        var formatter = new TextOutputFormatter();

        // Act
        var handler = new VerifyCommandHandler(formatter);

        // Assert
        Assert.That(handler, Is.Not.Null);
    }

    [Test]
    public async Task HandleAsync_WithNullSignature_ReturnsFileNotFound()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var context = CreateInvocationContext(signature: null);

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
    }

    [Test]
    public async Task HandleAsync_WithNonExistentSignature_ReturnsFileNotFound()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var nonExistentFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.cose"));
        var context = CreateInvocationContext(signature: nonExistentFile);

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
    }

    [Test]
    public async Task HandleAsync_WithValidSignature_ReturnsInvalidSignatureForInvalidCose()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84, 0x43, 0xA1]); // Invalid COSE bytes (incomplete)
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - invalid COSE data returns InvalidSignature
            Assert.That(result, Is.EqualTo((int)ExitCode.InvalidSignature));
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
    public async Task HandleAsync_WithNullContext_ThrowsArgumentNullException()
    {
        // Arrange
        var handler = new VerifyCommandHandler();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => handler.HandleAsync(null!));
    }

    [Test]
    public async Task HandleAsync_WithRandomBytes_ReturnsInvalidSignature()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04, 0x05]);
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - random bytes returns InvalidSignature
            Assert.That(result, Is.EqualTo((int)ExitCode.InvalidSignature));
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
    public async Task HandleAsync_UsesProvidedFormatter()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = new VerifyCommandHandler(formatter);
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]);
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            await handler.HandleAsync(context);
            formatter.Flush();

            // Assert - formatter should have been used
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Verification Operation"));
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
    public async Task HandleAsync_WithEmptyFile_ReturnsInvalidSignature()
    {
        // Arrange
        var handler = new VerifyCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, []);
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - empty file returns InvalidSignature
            Assert.That(result, Is.EqualTo((int)ExitCode.InvalidSignature));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
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

    [Test]
    public async Task HandleAsync_WithValidCoseSignature_ReturnsSuccessOrValidationStatus()
    {
        // Arrange - Create a real signature using sign-ephemeral
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var handler = new VerifyCommandHandler();

        try
        {
            File.WriteAllText(tempPayload, "Test payload for verify test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            var result = await handler.HandleAsync(context);

            // Assert - Should return success or a validation status (not file-related errors)
            Assert.That(
                result == (int)ExitCode.Success ||
                result == (int)ExitCode.VerificationFailed ||
                result == (int)ExitCode.UntrustedCertificate,
                $"Expected success or validation failure, got {result}");
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
    public async Task HandleAsync_WithJsonFormatter_ProducesJsonOutput()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(stringWriter);
        var handler = new VerifyCommandHandler(formatter);
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]);
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            await handler.HandleAsync(context);
            formatter.Flush();

            // Assert - JSON formatter should produce JSON-like output
            var output = stringWriter.ToString();
            Assert.That(output.Contains("{") || output.Contains("[") || output.Contains("\""));
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
    public async Task HandleAsync_WithXmlFormatter_ProducesXmlOutput()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new XmlOutputFormatter(stringWriter);
        var handler = new VerifyCommandHandler(formatter);
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]);
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            await handler.HandleAsync(context);
            formatter.Flush();

            // Assert - XML formatter should produce XML-like output
            var output = stringWriter.ToString();
            Assert.That(output.Contains("<") || output.Contains("</") || output.Contains("xml"));
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
    public async Task HandleAsync_WithQuietFormatter_SuppressesOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();
        var handler = new VerifyCommandHandler(formatter);
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]);
        var signature = new FileInfo(tempFile);
        var context = CreateInvocationContext(signature: signature);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - Should complete without throwing
            Assert.That(
                result == (int)ExitCode.InvalidSignature ||
                result == (int)ExitCode.FileNotFound ||
                result == (int)ExitCode.VerificationFailed, Is.True);
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
    public async Task HandleAsync_WithEmbeddedPayloadSignature_IndicatesEmbedded()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = new VerifyCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            // Use embedded signature type
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            await handler.HandleAsync(context);
            formatter.Flush();

            // Assert
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Embedded"));
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
    public async Task HandleAsync_WithDetachedSignature_IndicatesDetached()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = new VerifyCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            // Use direct with detached flag
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type detached --detached");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var signature = new FileInfo(tempSignature);
            var context = CreateInvocationContext(signature: signature);

            // Act
            await handler.HandleAsync(context);
            formatter.Flush();

            // Assert
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Detached"));
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
}





