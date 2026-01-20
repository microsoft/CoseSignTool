// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Commands.Handlers;

using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using System.Text.Json;
using CoseSignTool.Commands.Handlers;
using CoseSignTool.Inspection;
using CoseSignTool.Output;

/// <summary>
/// Tests for the InspectCommandHandler class.
/// </summary>
[TestFixture]
public class InspectCommandHandlerTests
{
    private sealed class BlockingStream : Stream
    {
        private readonly SemaphoreSlim _blockingSemaphore = new(0);

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await _blockingSemaphore.WaitAsync(cancellationToken);
            return 0;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _blockingSemaphore.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    [Test]
    public void Constructor_WithNullFormatter_UsesDefaultFormatter()
    {
        // Arrange & Act
        var handler = new InspectCommandHandler(new TestConsole(), null);

        // Assert
        Assert.That(handler, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithFormatter_UsesProvidedFormatter()
    {
        // Arrange
        var formatter = new TextOutputFormatter();

        // Act
        var handler = TestConsole.CreateInspectCommandHandler(formatter);

        // Assert
        Assert.That(handler, Is.Not.Null);
    }

    [Test]
    public async Task HandleAsync_WithNullFile_ReturnsFileNotFound()
    {
        // Arrange
        var handler = TestConsole.CreateInspectCommandHandler();
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
        var handler = TestConsole.CreateInspectCommandHandler();
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
        var handler = TestConsole.CreateInspectCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84, 0x43, 0xA1]); // Invalid COSE bytes (incomplete)
        var file = new FileInfo(tempFile);
        var context = CreateInvocationContext(file: file);

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
        var handler = TestConsole.CreateInspectCommandHandler();

        // Act & Assert
        Assert.ThrowsAsync<ArgumentNullException>(() => handler.HandleAsync(null!));
    }

    [Test]
    public async Task HandleAsync_WithRandomBytes_ReturnsInspectionFailed()
    {
        // Arrange
        var handler = TestConsole.CreateInspectCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04, 0x05]);
        var file = new FileInfo(tempFile);
        var context = CreateInvocationContext(file: file);

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
        var handler = TestConsole.CreateInspectCommandHandler(formatter);
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
        var handler = TestConsole.CreateInspectCommandHandler();
        var tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, []);
        var file = new FileInfo(tempFile);
        var context = CreateInvocationContext(file: file);

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

    [Test]
    public async Task HandleAsync_WithStdinAndNoData_ReturnsFileNotFoundAndWritesNoStdinDataError()
    {
        // Arrange
        var console = new TestConsole(Array.Empty<byte>());
        var outputWriter = new StringWriter();
        var errorWriter = new StringWriter();
        var formatter = new TextOutputFormatter(outputWriter, errorWriter);
        var handler = new InspectCommandHandler(console, formatter)
        {
            StdinTimeout = TimeSpan.FromMilliseconds(200)
        };

        var context = CreateInvocationContext(fileArgumentValue: "-");

        // Act
        var result = await handler.HandleAsync(context);
        formatter.Flush();

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
        var output = errorWriter.ToString();
        Assert.That(output, Does.Contain("No signature data received from stdin"));
    }

    [Test]
    public async Task HandleAsync_WithStdinData_UsesInspectionServiceAndReturnsInvalidSignatureForInvalidCose()
    {
        // Arrange
        var invalidCose = new byte[] { 0xD2, 0x84, 0x43, 0xA1 };
        var console = new TestConsole(invalidCose);
        var writer = new StringWriter();
        var formatter = new TextOutputFormatter(writer);
        var handler = new InspectCommandHandler(console, formatter)
        {
            StdinTimeout = TimeSpan.FromSeconds(1)
        };

        var context = CreateInvocationContext(fileArgumentValue: "-");

        // Act
        var result = await handler.HandleAsync(context);

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.InvalidSignature));
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

    private static InvocationContext CreateInvocationContext(string? fileArgumentValue)
    {
        var command = new Command("inspect");
        var fileArg = new Argument<string?>("file");
        command.AddArgument(fileArg);

        var args = fileArgumentValue is null ? "inspect" : $"inspect {fileArgumentValue}";
        var parseResult = command.Parse(args);
        return new InvocationContext(parseResult);
    }

    [Test]
    public async Task HandleAsync_WithValidCoseSignature_ReturnsSuccess()
    {
        // Arrange - Create a real signature using sign x509 ephemeral
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var handler = TestConsole.CreateInspectCommandHandler();

        try
        {
            File.WriteAllText(tempPayload, "Test payload for inspect test");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
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
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(stringWriter);
        var handler = TestConsole.CreateInspectCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
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
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new XmlOutputFormatter(stringWriter);
        var handler = TestConsole.CreateInspectCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
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
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var formatter = new QuietOutputFormatter();
        var handler = TestConsole.CreateInspectCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\"");
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
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = TestConsole.CreateInspectCommandHandler(formatter);

        try
        {
            // Create large payload
            File.WriteAllText(tempPayload, new string('A', 10000));
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\" --signature-type embedded");
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

    [Test]
    public async Task HandleAsync_WithExtractPayloadPath_ExtractsPayload()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var extractPath = Path.Combine(Path.GetTempPath(), $"extracted_{Guid.NewGuid()}.bin");
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = TestConsole.CreateInspectCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload to extract");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var file = new FileInfo(tempSignature);
            var context = CreateInvocationContext(file: file);

            // Act
            var result = await handler.HandleAsync(context, extractPath);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(extractPath), Is.True, "Extracted file should exist");
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

            if (File.Exists(extractPath))
            {
                File.Delete(extractPath);
            }
        }
    }

    [Test]
    public void StdinTimeout_CanBeConfigured()
    {
        // Arrange
        var handler = TestConsole.CreateInspectCommandHandler();

        // Act
        handler.StdinTimeout = TimeSpan.FromSeconds(5);

        // Assert
        Assert.That(handler.StdinTimeout, Is.EqualTo(TimeSpan.FromSeconds(5)));
    }

    private static InvocationContext CreateStdinContext()
    {
        var command = new Command("inspect");
        var fileArg = new Argument<string?>("file");

        command.AddArgument(fileArg);

        // Parse with "-" as the file argument (stdin indicator)
        var parseResult = command.Parse("inspect -");
        return new InvocationContext(parseResult);
    }

    private sealed class BlockingReadStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Test]
    public async Task HandleAsync_WithDetachedSignature_ExtractPayloadShowsWarning()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var extractPath = Path.Combine(Path.GetTempPath(), $"extracted_{Guid.NewGuid()}.bin");
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = TestConsole.CreateInspectCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\" --signature-type detached");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var file = new FileInfo(tempSignature);
            var context = CreateInvocationContext(file: file);

            // Act
            var result = await handler.HandleAsync(context, extractPath);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            Assert.That(File.Exists(extractPath), Is.False, "No file should be created for detached");
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Cannot extract"));
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

            if (File.Exists(extractPath))
            {
                File.Delete(extractPath);
            }
        }
    }

    [Test]
    public async Task HandleAsync_WithExtractPayloadNull_DoesNotExtract()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = TestConsole.CreateInspectCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var file = new FileInfo(tempSignature);
            var context = CreateInvocationContext(file: file);

            // Act
            var result = await handler.HandleAsync(context, extractPayloadPath: null);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Not.Contain("Payload extracted"));
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
    public async Task HandleAsync_WithIndirectSignature_ShowsHashInfo()
    {
        // Arrange
        var builder = TestConsole.CreateCommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var handler = TestConsole.CreateInspectCommandHandler(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign x509 ephemeral \"{tempPayload}\" --signature-type indirect");
            Assert.That(File.Exists(tempSignature), "Signature should exist");

            var file = new FileInfo(tempSignature);
            var context = CreateInvocationContext(file: file);

            // Act
            var result = await handler.HandleAsync(context);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("hash").Or.Contain("Hash").Or.Contain("SHA"));
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
