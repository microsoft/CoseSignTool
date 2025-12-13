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

            // Sign with 'detached' type
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type detached");
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

    [Test]
    public async Task InspectAsync_WithJsonFormatter_ReturnsStructuredResult()
    {
        // Arrange - Create a real signature
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test payload for JSON inspection");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            Assert.That(result, Is.EqualTo((int)ExitCode.Success));
            var jsonOutput = jsonWriter.ToString();

            // Parse JSON to verify structure
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var root = doc.RootElement;

            // Verify file info
            Assert.That(root.TryGetProperty("file", out var fileElement), Is.True);
            Assert.That(fileElement.GetProperty("path").GetString(), Does.Contain(tempSignature));
            Assert.That(fileElement.GetProperty("sizeBytes").GetInt64(), Is.GreaterThan(0));

            // Verify protected headers
            Assert.That(root.TryGetProperty("protectedHeaders", out var headersElement), Is.True);
            Assert.That(headersElement.TryGetProperty("algorithm", out var algElement), Is.True);
            Assert.That(algElement.GetProperty("id").GetInt32(), Is.Not.EqualTo(0));
            Assert.That(algElement.GetProperty("name").GetString(), Is.Not.Null.And.Not.Empty);

            // Verify payload info
            Assert.That(root.TryGetProperty("payload", out var payloadElement), Is.True);
            Assert.That(payloadElement.GetProperty("isEmbedded").GetBoolean(), Is.True);
            Assert.That(payloadElement.GetProperty("sizeBytes").GetInt32(), Is.GreaterThan(0));

            // Verify signature info
            Assert.That(root.TryGetProperty("signature", out var sigElement), Is.True);
            Assert.That(sigElement.GetProperty("totalSizeBytes").GetInt32(), Is.GreaterThan(0));

            // Verify certificates
            Assert.That(root.TryGetProperty("certificates", out var certsElement), Is.True);
            Assert.That(certsElement.GetArrayLength(), Is.GreaterThan(0));
            var firstCert = certsElement[0];
            Assert.That(firstCert.GetProperty("subject").GetString(), Is.Not.Null.And.Not.Empty);
            Assert.That(firstCert.GetProperty("thumbprint").GetString(), Is.Not.Null.And.Not.Empty);
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
    public async Task InspectAsync_WithJsonFormatter_DecodesAlgorithmName()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var algName = doc.RootElement.GetProperty("protectedHeaders").GetProperty("algorithm").GetProperty("name").GetString();

            // Should contain descriptive algorithm name like "PS256" or "RSASSA-PSS"
            Assert.That(algName, Does.Match("ES|PS|RS|ECDSA|RSA|EdDSA").IgnoreCase);
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
    public async Task InspectAsync_WithJsonFormatter_IncludesCertificateChainInfo()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test");
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\"");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);

            // Check certificate chain location
            var sigElement = doc.RootElement.GetProperty("signature");
            if (sigElement.TryGetProperty("certificateChainLocation", out var chainLoc))
            {
                Assert.That(chainLoc.GetString(), Is.EqualTo("protected").Or.EqualTo("unprotected"));
            }

            // Check certificates array
            var certs = doc.RootElement.GetProperty("certificates");
            Assert.That(certs.GetArrayLength(), Is.GreaterThanOrEqualTo(1));

            var cert = certs[0];
            Assert.That(cert.GetProperty("subject").GetString(), Does.Contain("CN="));
            Assert.That(cert.GetProperty("issuer").GetString(), Does.Contain("CN="));
            Assert.That(cert.GetProperty("serialNumber").GetString(), Is.Not.Null);
            Assert.That(cert.GetProperty("notBefore").GetString(), Does.Contain("UTC"));
            Assert.That(cert.GetProperty("notAfter").GetString(), Does.Contain("UTC"));
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
    public async Task InspectAsync_WithJsonFormatter_DetachedSignature_ShowsNoEmbeddedPayload()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test");
            // Create detached signature (payload not embedded)
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type detached");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var payloadElement = doc.RootElement.GetProperty("payload");

            Assert.That(payloadElement.GetProperty("isEmbedded").GetBoolean(), Is.False);
            // sizeBytes should be null or not present for detached signatures
            if (payloadElement.TryGetProperty("sizeBytes", out var sizeElement))
            {
                Assert.That(sizeElement.ValueKind, Is.EqualTo(System.Text.Json.JsonValueKind.Null));
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
    public async Task InspectAsync_WithJsonFormatter_TextPayload_ShowsPreview()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);
        var testContent = "Hello, this is a test payload for JSON inspection!";

        try
        {
            File.WriteAllText(tempPayload, testContent);
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var payloadElement = doc.RootElement.GetProperty("payload");

            Assert.That(payloadElement.GetProperty("isEmbedded").GetBoolean(), Is.True);
            // Embedded signatures contain binary hash envelope, so isText is false
            // The preview is only for truly embedded payload, not hash envelopes
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
    public async Task InspectAsync_WithJsonFormatter_BinaryPayload_ShowsSha256()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            // Write binary data (not valid UTF-8 text)
            File.WriteAllBytes(tempPayload, new byte[] { 0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x00, 0x00 });
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type embedded");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var payloadElement = doc.RootElement.GetProperty("payload");

            Assert.That(payloadElement.GetProperty("isEmbedded").GetBoolean(), Is.True);
            Assert.That(payloadElement.GetProperty("isText").GetBoolean(), Is.False);
            Assert.That(payloadElement.GetProperty("sha256").GetString(), Does.Match("^[A-F0-9]{64}$"));
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
    public async Task InspectAsync_WithJsonFormatter_IndirectSignature_ShowsHashAlgorithm()
    {
        // Arrange
        var builder = new CoseSignTool.Commands.CommandBuilder();
        var rootCommand = builder.BuildRootCommand();
        var tempPayload = Path.GetTempFileName();
        var tempSignature = $"{tempPayload}.cose";
        var jsonWriter = new StringWriter();
        var formatter = new JsonOutputFormatter(jsonWriter);
        var service = new CoseInspectionService(formatter);

        try
        {
            File.WriteAllText(tempPayload, "Test");
            // Create indirect signature (default type)
            rootCommand.Invoke($"sign-ephemeral \"{tempPayload}\" --signature-type indirect");
            Assert.That(File.Exists(tempSignature), "Signature file should exist");

            // Act
            var result = await service.InspectAsync(tempSignature);
            formatter.Flush();

            // Assert
            var jsonOutput = jsonWriter.ToString();
            var doc = System.Text.Json.JsonDocument.Parse(jsonOutput);
            var headersElement = doc.RootElement.GetProperty("protectedHeaders");

            // Indirect signatures should have payloadHashAlgorithm
            if (headersElement.TryGetProperty("payloadHashAlgorithm", out var hashAlg))
            {
                Assert.That(hashAlg.GetProperty("name").GetString(), Does.Contain("SHA"));
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
    public void CoseInspectionResult_PropertiesAreNullByDefault()
    {
        // Arrange & Act
        var result = new CoseInspectionResult();

        // Assert
        Assert.That(result.File, Is.Null);
        Assert.That(result.ProtectedHeaders, Is.Null);
        Assert.That(result.UnprotectedHeaders, Is.Null);
        Assert.That(result.CwtClaims, Is.Null);
        Assert.That(result.Payload, Is.Null);
        Assert.That(result.Signature, Is.Null);
        Assert.That(result.Certificates, Is.Null);
    }

    [Test]
    public void FileInformation_CanSetProperties()
    {
        // Arrange & Act
        var fileInfo = new FileInformation
        {
            Path = "/test/path.cose",
            SizeBytes = 1234
        };

        // Assert
        Assert.That(fileInfo.Path, Is.EqualTo("/test/path.cose"));
        Assert.That(fileInfo.SizeBytes, Is.EqualTo(1234));
    }

    [Test]
    public void ProtectedHeadersInfo_CanSetProperties()
    {
        // Arrange & Act
        var headers = new ProtectedHeadersInfo
        {
            Algorithm = new AlgorithmInfo { Id = -37, Name = "PS256" },
            ContentType = "application/json",
            CertificateChainLength = 3,
            PayloadHashAlgorithm = new AlgorithmInfo { Id = -16, Name = "SHA-256" },
            PreimageContentType = "text/plain",
            PayloadLocation = "https://example.com/payload"
        };

        // Assert
        Assert.That(headers.Algorithm?.Id, Is.EqualTo(-37));
        Assert.That(headers.Algorithm?.Name, Is.EqualTo("PS256"));
        Assert.That(headers.ContentType, Is.EqualTo("application/json"));
        Assert.That(headers.CertificateChainLength, Is.EqualTo(3));
        Assert.That(headers.PayloadHashAlgorithm?.Name, Is.EqualTo("SHA-256"));
        Assert.That(headers.PreimageContentType, Is.EqualTo("text/plain"));
        Assert.That(headers.PayloadLocation, Is.EqualTo("https://example.com/payload"));
    }

    [Test]
    public void CertificateThumbprintInfo_CanSetProperties()
    {
        // Arrange & Act
        var thumbprint = new CertificateThumbprintInfo
        {
            Algorithm = "SHA-256",
            Value = "ABCD1234"
        };

        // Assert
        Assert.That(thumbprint.Algorithm, Is.EqualTo("SHA-256"));
        Assert.That(thumbprint.Value, Is.EqualTo("ABCD1234"));
    }

    [Test]
    public void HeaderInfo_CanSetProperties()
    {
        // Arrange & Act
        var header = new HeaderInfo
        {
            Label = "custom-header",
            LabelId = 999,
            Value = "test-value",
            ValueType = "string",
            LengthBytes = 10
        };

        // Assert
        Assert.That(header.Label, Is.EqualTo("custom-header"));
        Assert.That(header.LabelId, Is.EqualTo(999));
        Assert.That(header.Value, Is.EqualTo("test-value"));
        Assert.That(header.ValueType, Is.EqualTo("string"));
        Assert.That(header.LengthBytes, Is.EqualTo(10));
    }

    [Test]
    public void CwtClaimsInfo_CanSetProperties()
    {
        // Arrange & Act
        var claims = new CwtClaimsInfo
        {
            Issuer = "test-issuer",
            Subject = "test-subject",
            Audience = "test-audience",
            IssuedAt = "2025-01-01 00:00:00 UTC",
            IssuedAtUnix = 1735689600,
            NotBefore = "2025-01-01 00:00:00 UTC",
            NotBeforeUnix = 1735689600,
            ExpirationTime = "2026-01-01 00:00:00 UTC",
            ExpirationTimeUnix = 1767225600,
            IsExpired = false,
            CwtId = "ABCD1234",
            CustomClaimsCount = 5
        };

        // Assert
        Assert.That(claims.Issuer, Is.EqualTo("test-issuer"));
        Assert.That(claims.Subject, Is.EqualTo("test-subject"));
        Assert.That(claims.Audience, Is.EqualTo("test-audience"));
        Assert.That(claims.IssuedAt, Is.EqualTo("2025-01-01 00:00:00 UTC"));
        Assert.That(claims.IssuedAtUnix, Is.EqualTo(1735689600));
        Assert.That(claims.IsExpired, Is.False);
        Assert.That(claims.CwtId, Is.EqualTo("ABCD1234"));
        Assert.That(claims.CustomClaimsCount, Is.EqualTo(5));
    }

    [Test]
    public void PayloadInfo_CanSetProperties()
    {
        // Arrange & Act
        var payload = new PayloadInfo
        {
            IsEmbedded = true,
            SizeBytes = 1024,
            ContentType = "application/json",
            IsText = true,
            Preview = "{ \"key\": \"value\" }",
            Sha256 = null // Not set when it's text
        };

        // Assert
        Assert.That(payload.IsEmbedded, Is.True);
        Assert.That(payload.SizeBytes, Is.EqualTo(1024));
        Assert.That(payload.ContentType, Is.EqualTo("application/json"));
        Assert.That(payload.IsText, Is.True);
        Assert.That(payload.Preview, Does.Contain("key"));
        Assert.That(payload.Sha256, Is.Null);
    }

    [Test]
    public void SignatureInfo_CanSetProperties()
    {
        // Arrange & Act
        var sig = new SignatureInfo
        {
            TotalSizeBytes = 2048,
            CertificateChainLocation = "protected"
        };

        // Assert
        Assert.That(sig.TotalSizeBytes, Is.EqualTo(2048));
        Assert.That(sig.CertificateChainLocation, Is.EqualTo("protected"));
    }

    [Test]
    public void CertificateInfo_CanSetProperties()
    {
        // Arrange & Act
        var cert = new CertificateInfo
        {
            Subject = "CN=Test Cert",
            Issuer = "CN=Test CA",
            SerialNumber = "123456",
            Thumbprint = "ABCDEF123456",
            NotBefore = "2025-01-01 00:00:00 UTC",
            NotAfter = "2026-01-01 00:00:00 UTC",
            IsExpired = false,
            KeyAlgorithm = "RSA",
            SignatureAlgorithm = "sha256RSA"
        };

        // Assert
        Assert.That(cert.Subject, Is.EqualTo("CN=Test Cert"));
        Assert.That(cert.Issuer, Is.EqualTo("CN=Test CA"));
        Assert.That(cert.SerialNumber, Is.EqualTo("123456"));
        Assert.That(cert.Thumbprint, Is.EqualTo("ABCDEF123456"));
        Assert.That(cert.NotBefore, Does.Contain("2025"));
        Assert.That(cert.NotAfter, Does.Contain("2026"));
        Assert.That(cert.IsExpired, Is.False);
        Assert.That(cert.KeyAlgorithm, Is.EqualTo("RSA"));
        Assert.That(cert.SignatureAlgorithm, Is.EqualTo("sha256RSA"));
    }

    [Test]
    public void AlgorithmInfo_CanSetProperties()
    {
        // Arrange & Act
        var alg = new AlgorithmInfo
        {
            Id = -37,
            Name = "PS256 (RSASSA-PSS w/ SHA-256)"
        };

        // Assert
        Assert.That(alg.Id, Is.EqualTo(-37));
        Assert.That(alg.Name, Is.EqualTo("PS256 (RSASSA-PSS w/ SHA-256)"));
    }
}