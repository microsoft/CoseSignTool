// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.IndirectSignature.Plugin.Tests;

[TestClass]
public class IndirectSignCommandTests
{
    private static readonly X509Certificate2 TestCertificate = TestCertificateUtils.CreateCertificate("IndirectSignCommandTests");
    private static readonly string TestCertificatePath = Path.GetTempFileName() + ".pfx";
    private static readonly string TestPayloadPath = Path.GetTempFileName();
    private static readonly string TestSignaturePath = Path.GetTempFileName() + ".cose";
    private static readonly string TestOutputPath = Path.GetTempFileName() + ".json";

    [ClassInitialize]
    public static void ClassInitialize(TestContext context)
    {
        // Export test certificate to file
        File.WriteAllBytes(TestCertificatePath, TestCertificate.Export(X509ContentType.Pkcs12));
        
        // Create test payload
        File.WriteAllText(TestPayloadPath, "Test payload content for indirect signing");
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        // Clean up test files
        SafeDeleteFile(TestCertificatePath);
        SafeDeleteFile(TestPayloadPath);
        SafeDeleteFile(TestSignaturePath);
        SafeDeleteFile(TestOutputPath);
    }

    [TestMethod]
    public void IndirectSignCommand_Properties_ShouldReturnCorrectValues()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();

        // Act & Assert
        Assert.AreEqual("indirect-sign", command.Name);
        Assert.IsTrue(command.Description.Contains("indirect COSE Sign1 signature"));
        Assert.IsNotNull(command.Usage);
        Assert.IsNotNull(command.Options);
        Assert.IsTrue(command.Options.Count > 0);
    }

    [TestMethod]
    public void IndirectSignCommand_Options_ShouldContainRequiredOptions()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();

        // Act
        IDictionary<string, string> options = command.Options;

        // Assert
        Assert.IsTrue(options.ContainsKey("payload"));
        Assert.IsTrue(options.ContainsKey("signature"));
        Assert.IsTrue(options.ContainsKey("pfx"));
        Assert.IsTrue(options.ContainsKey("thumbprint"));
        Assert.IsTrue(options.ContainsKey("content-type"));
        Assert.IsTrue(options.ContainsKey("hash-algorithm"));
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithValidPfxCertificate_ShouldSucceed()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["pfx"] = TestCertificatePath,
            ["output"] = TestOutputPath
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.Success, result);
        Assert.IsTrue(File.Exists(TestSignaturePath));
        Assert.IsTrue(File.Exists(TestOutputPath));

        // Verify the signature file is valid COSE
        byte[] signatureBytes = File.ReadAllBytes(TestSignaturePath);
        Assert.IsTrue(signatureBytes.Length > 0);

        CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
        Assert.IsNotNull(message);
        Assert.IsTrue(message.IsIndirectSignature());

        // Verify JSON output
        string jsonContent = File.ReadAllText(TestOutputPath);
        Assert.IsTrue(jsonContent.Contains("IndirectSign"));
        // Normalize path for JSON comparison (JSON escapes backslashes)
        string normalizedPayloadPath = TestPayloadPath.Replace("\\", "\\\\");
        Assert.IsTrue(jsonContent.Contains(normalizedPayloadPath));
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithMissingPayload_ShouldFail()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["signature"] = TestSignaturePath,
            ["pfx"] = TestCertificatePath
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithMissingCertificate_ShouldFail()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithNonExistentPayload_ShouldFail()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = "nonexistent-file.txt",
            ["signature"] = TestSignaturePath,
            ["pfx"] = TestCertificatePath
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithNonExistentCertificate_ShouldFail()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["pfx"] = "nonexistent-cert.pfx"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithCustomContentType_ShouldSucceed()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        string signaturePath = TestSignaturePath + "_custom";
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = signaturePath,
            ["pfx"] = TestCertificatePath,
            ["content-type"] = "application/json"
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(signaturePath));

            // Verify content type in signature
            byte[] signatureBytes = File.ReadAllBytes(signaturePath);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
            
            // The content type should be in the PreimageContentType header for CoseHashEnvelope format
            bool hasContentType = message.ProtectedHeaders.TryGetValue(new CoseHeaderLabel(259), out CoseHeaderValue contentTypeValue);
            Assert.IsTrue(hasContentType);
            string? contentType = contentTypeValue.GetValueAsString();
            Assert.IsTrue(contentType?.Contains("application/json") == true);
        }
        finally
        {
            SafeDeleteFile(signaturePath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithDifferentHashAlgorithms_ShouldSucceed()
    {
        // Test different hash algorithms
        string[] algorithms = new[] { "SHA256", "SHA384", "SHA512" };

        foreach (string algorithm in algorithms)
        {
            // Arrange
            IndirectSignCommand command = new IndirectSignCommand();
            string signaturePath = TestSignaturePath + $"_{algorithm}";
            IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
            {
                ["payload"] = TestPayloadPath,
                ["signature"] = signaturePath,
                ["pfx"] = TestCertificatePath,
                ["hash-algorithm"] = algorithm
            });

            try
            {
                // Act
                PluginExitCode result = await command.ExecuteAsync(configuration);

                // Assert
                Assert.AreEqual(PluginExitCode.Success, result, $"Failed for hash algorithm: {algorithm}");
                Assert.IsTrue(File.Exists(signaturePath), $"Signature file not created for algorithm: {algorithm}");

                // Verify the signature is valid
                byte[] signatureBytes = File.ReadAllBytes(signaturePath);
                CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);
                Assert.IsNotNull(message, $"Invalid COSE message for algorithm: {algorithm}");
                Assert.IsTrue(message.IsIndirectSignature(), $"Not an indirect signature for algorithm: {algorithm}");
            }
            finally
            {
                SafeDeleteFile(signaturePath);
            }
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithInvalidHashAlgorithm_ShouldFail()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["pfx"] = TestCertificatePath,
            ["hash-algorithm"] = "INVALID"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithTimeout_ShouldRespectTimeout()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["pfx"] = TestCertificatePath,
            ["timeout"] = "1"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        // The operation should complete within the timeout for a small file
        Assert.AreEqual(PluginExitCode.Success, result);
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithInvalidTimeout_ShouldFail()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["pfx"] = TestCertificatePath,
            ["timeout"] = "invalid"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    private static IConfiguration CreateConfiguration(Dictionary<string, string?> values)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(values!)
            .Build();
    }

    private static void SafeDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Ignore cleanup errors
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithJsonOutput_ShouldContainCorrectStructure()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["pfx"] = TestCertificatePath,
            ["output"] = TestOutputPath
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(TestOutputPath));

            // Parse and verify JSON structure
            string jsonContent = File.ReadAllText(TestOutputPath);
            JsonDocument jsonDoc = JsonDocument.Parse(jsonContent);
            JsonElement root = jsonDoc.RootElement;

            // Verify top-level structure
            Assert.IsTrue(root.TryGetProperty("operation", out JsonElement operation));
            Assert.AreEqual("IndirectSign", operation.GetString());

            Assert.IsTrue(root.TryGetProperty("success", out JsonElement success));
            Assert.IsTrue(success.GetBoolean());

            Assert.IsTrue(root.TryGetProperty("result", out JsonElement resultElement));

            // Verify nested result structure
            Assert.IsTrue(resultElement.TryGetProperty("Operation", out JsonElement resultOperation));
            Assert.AreEqual("IndirectSign", resultOperation.GetString());

            Assert.IsTrue(resultElement.TryGetProperty("PayloadPath", out JsonElement payloadPath));
            Assert.AreEqual(TestPayloadPath, payloadPath.GetString());

            Assert.IsTrue(resultElement.TryGetProperty("SignaturePath", out JsonElement signaturePath));
            Assert.AreEqual(TestSignaturePath, signaturePath.GetString());

            Assert.IsTrue(resultElement.TryGetProperty("ContentType", out JsonElement contentType));
            Assert.AreEqual("application/octet-stream", contentType.GetString());

            Assert.IsTrue(resultElement.TryGetProperty("HashAlgorithm", out JsonElement hashAlgorithm));
            Assert.AreEqual("SHA256", hashAlgorithm.GetString());

            Assert.IsTrue(resultElement.TryGetProperty("SignatureVersion", out JsonElement signatureVersion));
            Assert.AreEqual("CoseHashEnvelope", signatureVersion.GetString());

            Assert.IsTrue(resultElement.TryGetProperty("SignatureSize", out JsonElement signatureSize));
            Assert.IsTrue(signatureSize.GetInt32() > 0);

            Assert.IsTrue(resultElement.TryGetProperty("CertificateThumbprint", out JsonElement thumbprint));
            Assert.IsFalse(string.IsNullOrEmpty(thumbprint.GetString()));

            Assert.IsTrue(resultElement.TryGetProperty("CreationTime", out JsonElement creationTime));
            Assert.IsTrue(DateTime.TryParse(creationTime.GetString(), out DateTime parsedTime));
            Assert.IsTrue(parsedTime <= DateTime.UtcNow);
        }
        finally
        {
            SafeDeleteFile(TestOutputPath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithCustomContentType_ShouldReflectInJsonOutput()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        string customContentType = "application/json";
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["pfx"] = TestCertificatePath,
            ["content-type"] = customContentType,
            ["output"] = TestOutputPath
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);

            // Verify JSON contains custom content type
            string jsonContent = File.ReadAllText(TestOutputPath);
            JsonDocument jsonDoc = JsonDocument.Parse(jsonContent);
            JsonElement root = jsonDoc.RootElement;

            Assert.IsTrue(root.TryGetProperty("result", out JsonElement resultElement));
            Assert.IsTrue(resultElement.TryGetProperty("ContentType", out JsonElement contentType));
            Assert.AreEqual(customContentType, contentType.GetString());
        }
        finally
        {
            SafeDeleteFile(TestOutputPath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithDifferentHashAlgorithms_ShouldReflectInJsonOutput()
    {
        string[] algorithms = new[] { "SHA256", "SHA384", "SHA512" };

        foreach (string algorithm in algorithms)
        {
            // Arrange
            IndirectSignCommand command = new IndirectSignCommand();
            string signaturePath = TestSignaturePath + $"_{algorithm}";
            string outputPath = TestOutputPath + $"_{algorithm}";
            
            IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
            {
                ["payload"] = TestPayloadPath,
                ["signature"] = signaturePath,
                ["pfx"] = TestCertificatePath,
                ["hash-algorithm"] = algorithm,
                ["output"] = outputPath
            });

            try
            {
                // Act
                PluginExitCode result = await command.ExecuteAsync(configuration);

                // Assert
                Assert.AreEqual(PluginExitCode.Success, result, $"Failed for algorithm {algorithm}");

                // Verify JSON contains correct hash algorithm
                string jsonContent = File.ReadAllText(outputPath);
                JsonDocument jsonDoc = JsonDocument.Parse(jsonContent);
                JsonElement root = jsonDoc.RootElement;

                Assert.IsTrue(root.TryGetProperty("result", out JsonElement resultElement));
                Assert.IsTrue(resultElement.TryGetProperty("HashAlgorithm", out JsonElement hashAlgorithm));
                Assert.AreEqual(algorithm, hashAlgorithm.GetString(), $"Hash algorithm mismatch for {algorithm}");
            }
            finally
            {
                SafeDeleteFile(signaturePath);
                SafeDeleteFile(outputPath);
            }
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_FailureCase_ShouldReturnNullJsonElement()
    {
        // Arrange - use non-existent certificate to force failure
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["pfx"] = "nonexistent-cert.pfx",
            ["output"] = TestOutputPath
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreNotEqual(PluginExitCode.Success, result);
        
        // JSON output file should not be created on failure
        Assert.IsFalse(File.Exists(TestOutputPath), "Output file should not be created on failure");
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithoutOutputPath_ShouldNotCreateJsonFile()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["pfx"] = TestCertificatePath
            // Note: no "output" parameter
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.Success, result);
        Assert.IsFalse(File.Exists(TestOutputPath), "Output file should not be created when no output path specified");
    }
}
