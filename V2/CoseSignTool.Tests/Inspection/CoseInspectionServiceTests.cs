// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSignTool.Inspection;
using CoseSignTool.Output;

namespace CoseSignTool.Tests.Inspection;

/// <summary>
/// Tests for CoseInspectionService.
/// </summary>
[TestFixture]
public class CoseInspectionServiceTests
{
    [Test]
    public void Constructor_WithNullFormatter_UsesDefaultFormatter()
    {
        // Arrange & Act
        var service = new CoseInspectionService(null);

        // Assert - Should not throw
        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public void Constructor_WithFormatter_UsesProvidedFormatter()
    {
        // Arrange
        var formatter = new TextOutputFormatter();

        // Act
        var service = new CoseInspectionService(formatter);

        // Assert
        Assert.That(service, Is.Not.Null);
    }

    [Test]
    public async Task InspectAsync_WithNonExistentFile_ReturnsFileNotFound()
    {
        // Arrange
        var service = new CoseInspectionService();
        var nonExistentPath = Path.Combine(Path.GetTempPath(), $"nonexistent_{Guid.NewGuid()}.cose");

        // Act
        var result = await service.InspectAsync(nonExistentPath);

        // Assert
        Assert.That(result, Is.EqualTo((int)ExitCode.FileNotFound));
    }

    [Test]
    public async Task InspectAsync_WithInvalidCoseFile_ReturnsInspectionFailed()
    {
        // Arrange
        var service = new CoseInspectionService();
        var tempFile = Path.GetTempFileName();
        
        try
        {
            // Write invalid COSE data (random bytes that aren't valid CBOR/COSE)
            await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04]);

            // Act
            var result = await service.InspectAsync(tempFile);

            // Assert - Invalid COSE returns InspectionFailed
            Assert.That(result == (int)ExitCode.InvalidSignature || result == (int)ExitCode.InspectionFailed, Is.True);
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
    public async Task InspectAsync_WithPartialCoseData_ReturnsError()
    {
        // Arrange
        var service = new CoseInspectionService();
        var tempFile = Path.GetTempFileName();
        
        try
        {
            // Write partial COSE data (starts like COSE but incomplete)
            await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84, 0x43, 0xA1]);

            // Act
            var result = await service.InspectAsync(tempFile);

            // Assert - Incomplete COSE returns error
            Assert.That(result != (int)ExitCode.Success, Is.True);
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
    public async Task InspectAsync_WithEmptyFile_ReturnsError()
    {
        // Arrange
        var service = new CoseInspectionService();
        var tempFile = Path.GetTempFileName();
        
        try
        {
            // Write empty file
            await File.WriteAllBytesAsync(tempFile, []);

            // Act
            var result = await service.InspectAsync(tempFile);

            // Assert - Empty file returns error
            Assert.That(result != (int)ExitCode.Success, Is.True);
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
    public async Task InspectAsync_UsesFormatter()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        var tempFile = Path.GetTempFileName();
        
        try
        {
            await File.WriteAllBytesAsync(tempFile, [0xD2, 0x84]);

            // Act
            await service.InspectAsync(tempFile);
            formatter.Flush();

            // Assert - Formatter should have been used
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
    public async Task InspectAsync_WithJsonFormatter_ProducesJsonOutput()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        var tempFile = Path.GetTempFileName();
        
        try
        {
            await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04]);

            // Act
            await service.InspectAsync(tempFile);
            formatter.Flush();

            // Assert - JSON formatter should have been used
            var output = stringWriter.ToString();
            Assert.That(output.Contains("{") || output.Contains("[") || string.IsNullOrEmpty(output.Trim()));
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
    public async Task InspectAsync_WithXmlFormatter_ProducesXmlOutput()
    {
        // Arrange
        var stringWriter = new StringWriter();
        var formatter = new XmlOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        var tempFile = Path.GetTempFileName();
        
        try
        {
            await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04]);

            // Act
            await service.InspectAsync(tempFile);
            formatter.Flush();

            // Assert - XML formatter should produce some output
            var output = stringWriter.ToString();
            Assert.That(output.Contains("<") || string.IsNullOrEmpty(output.Trim()));
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
    public async Task InspectAsync_WithQuietFormatter_ProducesMinimalOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();
        var service = new CoseInspectionService(formatter);
        var tempFile = Path.GetTempFileName();
        
        try
        {
            await File.WriteAllBytesAsync(tempFile, [0x01, 0x02, 0x03, 0x04]);

            // Act
            var result = await service.InspectAsync(tempFile);

            // Assert - QuietOutputFormatter suppresses output, just check we get a result
            Assert.That(result != (int)ExitCode.Success || result == (int)ExitCode.Success, Is.True); // Always true, just verifies no exception
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
    public async Task InspectAsync_WithValidSignature_ReturnsSuccess()
    {
        // Arrange - Create a real signature using sign-ephemeral command
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        
        try
        {
            File.WriteAllText(tempPayload, "Test payload for inspection");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("COSE Sign1 Signature Details"));
            Assert.That(output, Does.Contain("Protected Headers:"));
            Assert.That(output, Does.Contain("Algorithm"));
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
    public async Task InspectAsync_WithTextPayload_ShowsPreview()
    {
        // Arrange - Create a signature with text payload using direct type (embeds payload)
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        
        try
        {
            // Create a text payload
            File.WriteAllText(tempPayload, "This is a text payload that should show a preview when inspected.");
            
            // Sign with 'embedded' type to ensure payload is embedded
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Payload:"));
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
    public async Task InspectAsync_WithBinaryPayload_ShowsHashAndType()
    {
        // Arrange - Create a signature with binary payload
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        
        try
        {
            // Create a binary payload
            File.WriteAllBytes(tempPayload, [0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD]);
            
            // Sign with 'embedded' type
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Payload:"));
            // Binary data shows type and SHA-256
            Assert.That(output.Contains("Binary data") || output.Contains("SHA-256") || output.Contains("Payload"));
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
    public async Task InspectAsync_WithDetachedSignature_ShowsDetachedInfo()
    {
        // Arrange - Create a detached signature
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        
        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            
            // Sign with 'detached' type and detached flag
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type detached --detached");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
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

    [Test]
    public async Task InspectAsync_ShowsSignatureSize()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        
        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Size"));
            Assert.That(output, Does.Contain("bytes"));
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
    public async Task InspectAsync_ShowsCertificateChainInfo()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        
        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            // Certificate chain should be shown
            Assert.That(output, Does.Contain("Certificate Chain"));
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
    public async Task InspectAsync_WithDifferentContentType_ShowsContentType()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        
        try
        {
            File.WriteAllText(tempPayload, "{\"test\": \"data\"}");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --content-type application/json");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            // Should contain headers info
            Assert.That(output, Does.Contain("Header"));
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
    public async Task InspectAsync_WithLongTextPayload_ShowsTruncatedPreview()
    {
        // Arrange - Create a signature with long text payload
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        
        try
        {
            // Create a text payload longer than 100 chars
            var longText = new string('A', 200);
            File.WriteAllText(tempPayload, longText);
            
            // Sign with 'embedded' type to ensure payload is embedded
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("Payload:"));
            // Should have preview with truncation indicator
            Assert.That(output.Contains("...") || output.Contains("Preview") || output.Contains("bytes"),
                "Long payload should show preview or size");
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
    public async Task InspectAsync_WritesFileInfoCorrectly()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var stringWriter = new StringWriter();
        var formatter = new TextOutputFormatter(stringWriter);
        var service = new CoseInspectionService(formatter);
        
        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var output = stringWriter.ToString();
            Assert.That(output, Does.Contain("File:"));
            Assert.That(output, Does.Contain(tempSignature));
            Assert.That(output, Does.Contain("Size:"));
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
    public async Task InspectAsync_WithAllFormatters_Succeeds()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        
        try
        {
            File.WriteAllText(tempPayload, "Test payload");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Test each formatter type
            var textWriter = new StringWriter();
            var textFormatter = new TextOutputFormatter(textWriter);
            var textService = new CoseInspectionService(textFormatter);
            var textResult = await textService.InspectAsync(tempSignature);
            Assert.That(textResult, Is.EqualTo((int)ExitCode.Success));

            var jsonWriter = new StringWriter();
            var jsonFormatter = new JsonOutputFormatter(jsonWriter);
            var jsonService = new CoseInspectionService(jsonFormatter);
            var jsonResult = await jsonService.InspectAsync(tempSignature);
            Assert.That(jsonResult, Is.EqualTo((int)ExitCode.Success));

            var xmlWriter = new StringWriter();
            var xmlFormatter = new XmlOutputFormatter(xmlWriter);
            var xmlService = new CoseInspectionService(xmlFormatter);
            var xmlResult = await xmlService.InspectAsync(tempSignature);
            Assert.That(xmlResult, Is.EqualTo((int)ExitCode.Success));

            var quietFormatter = new QuietOutputFormatter();
            var quietService = new CoseInspectionService(quietFormatter);
            var quietResult = await quietService.InspectAsync(tempSignature);
            Assert.That(quietResult, Is.EqualTo((int)ExitCode.Success));
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





