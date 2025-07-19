// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.IndirectSignature.Plugin.Tests;

[TestClass]
public class IndirectVerifyCommandTests
{
    private static readonly X509Certificate2 TestCertificate = TestCertificateUtils.CreateCertificate("IndirectVerifyCommandTests");
    private static readonly string TestCertificatePath = Path.GetTempFileName() + ".pfx";
    private static readonly string TestPayloadPath = Path.GetTempFileName();
    private static readonly string TestSignaturePath = Path.GetTempFileName() + ".cose";
    private static readonly string TestOutputPath = Path.GetTempFileName() + ".json";
    private static readonly string TestRootCertsPath = Path.GetTempFileName() + ".pem";

    [ClassInitialize]
    public static void ClassInitialize(TestContext context)
    {
        // Export test certificate to file
        File.WriteAllBytes(TestCertificatePath, TestCertificate.Export(X509ContentType.Pkcs12));
        
        // Create test payload
        File.WriteAllText(TestPayloadPath, "Test payload content for indirect verification");

        // Create a test indirect signature
        CreateTestIndirectSignature();

        // Create test root certificates file
        File.WriteAllBytes(TestRootCertsPath, TestCertificate.Export(X509ContentType.Cert));
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        // Clean up test files
        SafeDeleteFile(TestCertificatePath);
        SafeDeleteFile(TestPayloadPath);
        SafeDeleteFile(TestSignaturePath);
        SafeDeleteFile(TestOutputPath);
        SafeDeleteFile(TestRootCertsPath);
    }

    [TestMethod]
    public void IndirectVerifyCommand_Properties_ShouldReturnCorrectValues()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();

        // Act & Assert
        Assert.AreEqual("indirect-verify", command.Name);
        Assert.IsTrue(command.Description.Contains("indirect COSE Sign1 signature"));
        Assert.IsNotNull(command.Usage);
        Assert.IsNotNull(command.Options);
        Assert.IsTrue(command.Options.Count > 0);
    }

    [TestMethod]
    public void IndirectVerifyCommand_Options_ShouldContainRequiredOptions()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();

        // Act
        IDictionary<string, string> options = command.Options;

        // Assert
        Assert.IsTrue(options.ContainsKey("payload"));
        Assert.IsTrue(options.ContainsKey("signature"));
        Assert.IsTrue(options.ContainsKey("roots"));
        Assert.IsTrue(options.ContainsKey("allow-untrusted"));
        Assert.IsTrue(options.ContainsKey("allow-outdated"));
        Assert.IsTrue(options.ContainsKey("common-name"));
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithValidSignature_ShouldSucceed()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["allow-untrusted"] = "true",
            ["output"] = TestOutputPath
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.Success, result);
        Assert.IsTrue(File.Exists(TestOutputPath));

        // Verify JSON output
        string jsonContent = File.ReadAllText(TestOutputPath);
        Assert.IsTrue(jsonContent.Contains("IndirectVerify"));
        Assert.IsTrue(jsonContent.Contains("\"isValid\": true"));
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithMissingPayload_ShouldFail()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["signature"] = TestSignaturePath
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithMissingSignature_ShouldFail()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithNonExistentPayload_ShouldFail()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = "nonexistent-file.txt",
            ["signature"] = TestSignaturePath
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithNonExistentSignature_ShouldFail()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = "nonexistent-signature.cose"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithModifiedPayload_ShouldFail()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        string modifiedPayloadPath = TestPayloadPath + "_modified";
        File.WriteAllText(modifiedPayloadPath, "Modified payload content");

        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = modifiedPayloadPath,
            ["signature"] = TestSignaturePath,
            ["allow-untrusted"] = "true"
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.IndirectSignatureVerificationFailure, result);
        }
        finally
        {
            SafeDeleteFile(modifiedPayloadPath);
        }
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithRootCertificates_ShouldSucceed()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["roots"] = TestRootCertsPath,
            ["allow-untrusted"] = "true"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.Success, result);
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithNonExistentRootCerts_ShouldFail()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["roots"] = "nonexistent-roots.pem"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithCommonName_ShouldSucceed()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["common-name"] = "IndirectVerifyCommandTests",
            ["allow-untrusted"] = "true"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.Success, result);
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithWrongCommonName_ShouldFail()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["common-name"] = "WrongName",
            ["allow-untrusted"] = "true"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.IndirectSignatureVerificationFailure, result);
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithInvalidTimeout_ShouldFail()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["timeout"] = "invalid"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithRegularSignature_ShouldFail()
    {
        // Create a regular (non-indirect) signature
        string regularSignaturePath = TestSignaturePath + "_regular";
        CreateTestRegularSignature(regularSignaturePath);

        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = regularSignaturePath
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
        }
        finally
        {
            SafeDeleteFile(regularSignaturePath);
        }
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithAllowOutdated_ShouldSucceed()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["allow-untrusted"] = "true",
            ["allow-outdated"] = "true"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.Success, result);
    }

    private static void CreateTestIndirectSignature()
    {
        try
        {
            byte[] payload = File.ReadAllBytes(TestPayloadPath);
            X509Certificate2CoseSigningKeyProvider signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(TestCertificate);
            
            using IndirectSignatureFactory factory = new IndirectSignatureFactory();
            CoseSign1Message indirectSignature = factory.CreateIndirectSignature(
                payload: payload,
                signingKeyProvider: signingKeyProvider,
                contentType: "text/plain");

            byte[] signatureBytes = indirectSignature.Encode();
            File.WriteAllBytes(TestSignaturePath, signatureBytes);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to create test indirect signature: {ex.Message}", ex);
        }
    }

    private static void CreateTestRegularSignature(string signaturePath)
    {
        try
        {
            byte[] payload = File.ReadAllBytes(TestPayloadPath);
            X509Certificate2CoseSigningKeyProvider signingKeyProvider = new X509Certificate2CoseSigningKeyProvider(TestCertificate);

            CoseSign1MessageFactory factory = new CoseSign1MessageFactory();
            CoseSign1Message regularSignature = factory.CreateCoseSign1Message(
                payload: payload,
                signingKeyProvider: signingKeyProvider);

            byte[] signatureBytes = regularSignature.Encode();
            File.WriteAllBytes(signaturePath, signatureBytes);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to create test regular signature: {ex.Message}", ex);
        }
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
    public async Task IndirectVerifyCommand_Execute_WithJsonOutput_ShouldContainCorrectStructure()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["allow-untrusted"] = "true",
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
            Assert.AreEqual("IndirectVerify", operation.GetString());

            Assert.IsTrue(root.TryGetProperty("payloadPath", out JsonElement payloadPath));
            Assert.AreEqual(TestPayloadPath, payloadPath.GetString());

            Assert.IsTrue(root.TryGetProperty("signaturePath", out JsonElement signaturePath));
            Assert.AreEqual(TestSignaturePath, signaturePath.GetString());

            Assert.IsTrue(root.TryGetProperty("isValid", out JsonElement isValid));
            Assert.IsTrue(isValid.GetBoolean());

            Assert.IsTrue(root.TryGetProperty("result", out JsonElement resultElement));
            Assert.IsNotNull(resultElement);
        }
        finally
        {
            SafeDeleteFile(TestOutputPath);
        }
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithInvalidSignature_ShouldReflectInJsonOutput()
    {
        // Arrange - Create a modified payload to make signature invalid
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        string modifiedPayloadPath = TestPayloadPath + "_modified";
        File.WriteAllText(modifiedPayloadPath, "Modified content that will make signature invalid");

        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = modifiedPayloadPath,
            ["signature"] = TestSignaturePath,
            ["allow-untrusted"] = "true",
            ["output"] = TestOutputPath
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreNotEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(TestOutputPath));

            // Parse and verify JSON structure shows invalid signature
            string jsonContent = File.ReadAllText(TestOutputPath);
            JsonDocument jsonDoc = JsonDocument.Parse(jsonContent);
            JsonElement root = jsonDoc.RootElement;

            Assert.IsTrue(root.TryGetProperty("operation", out JsonElement operation));
            Assert.AreEqual("IndirectVerify", operation.GetString());

            Assert.IsTrue(root.TryGetProperty("isValid", out JsonElement isValid));
            Assert.IsFalse(isValid.GetBoolean(), "Signature should be invalid for modified payload");
        }
        finally
        {
            SafeDeleteFile(modifiedPayloadPath);
            SafeDeleteFile(TestOutputPath);
        }
    }

    [TestMethod]
    public async Task IndirectVerifyCommand_Execute_WithoutOutputPath_ShouldNotCreateJsonFile()
    {
        // Arrange
        IndirectVerifyCommand command = new IndirectVerifyCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["allow-untrusted"] = "true"
            // Note: no "output" parameter
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.Success, result);
        Assert.IsFalse(File.Exists(TestOutputPath), "Output file should not be created when no output path specified");
    }
}
