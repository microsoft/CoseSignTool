// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.Text.Json;
using CoseSignTool.Commands.Handlers;
using CoseSignTool.Inspection;
using CoseSignTool.Output;

namespace CoseSignTool.Tests.Commands.Handlers;

/// <summary>
/// Tests for the InspectCommandHandler class.
/// </summary>
[TestFixture]
public class InspectCommandHandlerTests
{
    [Test]
    public void Constructor_WithNullFormatter_UsesDefaultFormatter()
    {
        // Arrange & Act
        var handler = new InspectCommandHandler(null);

        // Assert
        Assert.That(handler, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithFormatter_UsesProvidedFormatter()
    {
        // Arrange
        var formatter = new TextOutputFormatter();

        // Act
        var handler = new InspectCommandHandler(formatter);

        // Assert
        Assert.That(handler, Is.Not.Null);
    }

    [Test]
    public async Task HandleAsync_WithNullFile_ReturnsFileNotFound()
    {
        // Arrange
        var handler = new InspectCommandHandler();
        var context = CreateInvocationContext(file: null);

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
    }

    [Test]
    public async Task HandleAsync_WithNonExistentFile_ReturnsFileNotFound()
    {
        // Arrange
        var handler = new InspectCommandHandler();
        var nonExistentFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.cose"));
        var context = CreateInvocationContext(file: nonExistentFile);

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
    }

    [Test]
    public async Task HandleAsync_WithValidFile_ReturnsInspectionFailedForInvalidCose()
    {
        // Arrange
        var handler = new InspectCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84, 0x43, 0xA1]); // Invalid COSE bytes (incomplete)
        var file = new FileInfo(tempFile);
        var context = CreateInvocationContext(file: file);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - invalid COSE data returns InspectionFailed
            Assert.That(result, Is.EqualTo((int)ExitCode.InspectionFailed));
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
        var handler = new InspectCommandHandler();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => handler.HandleAsync(null!));
    }

    [Test]
    public async Task HandleAsync_WithRandomBytes_ReturnsInspectionFailed()
    {
        // Arrange
        var handler = new InspectCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04, 0x05]);
        var file = new FileInfo(tempFile);
        var context = CreateInvocationContext(file: file);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - random bytes returns InspectionFailed
            Assert.That(result, Is.EqualTo((int)ExitCode.InspectionFailed));
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
        var handler = new InspectCommandHandler(formatter);
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]);
        var file = new FileInfo(tempFile);
        var context = CreateInvocationContext(file: file);

        try
        {
            // Act
            await handler.HandleAsync(context);
            formatter.Flush();

            // Assert - formatter should have been used
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("COSE Sign1 Signature Details"));
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
    public async Task HandleAsync_WithEmptyFile_ReturnsInspectionFailed()
    {
        // Arrange
        var handler = new InspectCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, []);
        var file = new FileInfo(tempFile);
        var context = CreateInvocationContext(file: file);

        try
        {
            // Act
            var result = await handler.HandleAsync(context);

            // Assert - empty file returns InspectionFailed
            Assert.That(result, Is.EqualTo((int)ExitCode.InspectionFailed));
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    private static InvocationContext CreateInvocationContext(FileInfo? file = null)
    {
        var command = new Command("inspect");
        var fileArg = new Argument<string?>("file");

        command.AddArgument(fileArg);

        var args = file != null ? $"inspect \"{file.FullName}\"" : "inspect";
        var parseResult = command.Parse(args);
        return new InvocationContext(parseResult);
    }

    [Test]
    public async Task HandleAsync_WithValidCoseSignature_ReturnsSuccess()
    {
        // Arrange - Create a real signature using sign-ephemeral
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var handler = new InspectCommandHandler();

        try
        {
            File.WriteAllText(tempPayload, "Test payload for inspect test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var file = new FileInfo(tempSignature);
            var context = CreateInvocationContext(file: file);

            // Act
            var result = await handler.HandleAsync(context);

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
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
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(stringWriter);
        var handler = new InspectCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var file = new FileInfo(tempSignature);
            var context = CreateInvocationContext(file: file);

            // Act
            await handler.HandleAsync(context);

            // Assert
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("\"certificates\""), $"JSON output did not contain 'certificates'. Output:\n{output}");

            var result = JsonSerializer.Deserialize<CoseInspectionResult>(output);
            Assert.That(result, Is.Not.Null, $"Unable to deserialize JSON output. Output:\n{output}");

            Assert.That(result!.ProtectedHeaders, Is.Not.Null, $"Missing protectedHeaders. Output:\n{output}");
            Assert.That(result.ProtectedHeaders!.CertificateChainLength, Is.Not.Null.And.GreaterThan(0), $"Missing/invalid certificateChainLength. Output:\n{output}");
            Assert.That(result.ProtectedHeaders.CertificateThumbprint, Is.Not.Null, $"Missing certificateThumbprint (x5t). Output:\n{output}");
            Assert.That(result.ProtectedHeaders.CertificateThumbprint!.Algorithm, Is.Not.Empty, $"Missing x5t algorithm. Output:\n{output}");
            Assert.That(result.ProtectedHeaders.CertificateThumbprint.Value, Is.Not.Empty, $"Missing x5t value. Output:\n{output}");

            Assert.That(result.Certificates, Is.Not.Null.And.Not.Empty, $"Missing decoded certificates from x5chain. Output:\n{output}");
            Assert.That(result.Certificates!.Count, Is.GreaterThanOrEqualTo(result.ProtectedHeaders.CertificateChainLength!.Value), $"Decoded certificate count did not match chain length. Output:\n{output}");

            foreach (var cert in result.Certificates)
            {
                Assert.That(cert.Subject, Is.Not.Empty);
                Assert.That(cert.Issuer, Is.Not.Empty);
                Assert.That(cert.Thumbprint, Is.Not.Empty);
                Assert.That(cert.NotBefore, Is.Not.Empty);
                Assert.That(cert.NotAfter, Is.Not.Empty);
            }
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
    public async Task HandleAsync_WithXmlFormatter_ProducesXmlOutput()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new XmlOutputFormatter(stringWriter);
        var handler = new InspectCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var file = new FileInfo(tempSignature);
            var context = CreateInvocationContext(file: file);

            // Act
            await handler.HandleAsync(context);

            // Assert
            var output = stringWriter.ToString();
            Assert.That(output.Contains("<") || output.Contains("xml"));
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
    public async Task HandleAsync_WithQuietFormatter_ReturnsResult()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var formatter = new QuietOutputFormatter();
        var handler = new InspectCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var file = new FileInfo(tempSignature);
            var context = CreateInvocationContext(file: file);

            // Act
            var result = await handler.HandleAsync(context);

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
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
    public async Task HandleAsync_WithLargePayload_ReturnsSuccess()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = new InspectCommandHandler(formatter);

        try
        {
            // Create large payload
            File.WriteAllText(tempPayload, new string('A', 10000));
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var file = new FileInfo(tempSignature);
            var context = CreateInvocationContext(file: file);

            // Act
            var result = await handler.HandleAsync(context);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Payload"));
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