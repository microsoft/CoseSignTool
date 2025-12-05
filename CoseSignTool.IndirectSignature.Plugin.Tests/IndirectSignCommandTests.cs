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

    [TestMethod]
    public void IndirectSignCommand_Options_ShouldContainCWTClaimsOptions()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();

        // Act
        IDictionary<string, string> options = command.Options;

        // Assert
        Assert.IsTrue(options.ContainsKey("enable-scitt"));
        Assert.IsTrue(options.ContainsKey("cwt-issuer"));
        Assert.IsTrue(options.ContainsKey("cwt-subject"));
        Assert.IsTrue(options.ContainsKey("cwt-audience"));
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithCWTClaims_ShouldIncludeClaimsInSignature()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        string signaturePath = TestSignaturePath + "_cwt";
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = signaturePath,
            ["pfx"] = TestCertificatePath,
            ["cwt-issuer"] = "did:example:issuer",
            ["cwt-subject"] = "test.subject",
            ["cwt-audience"] = "test-audience"
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(signaturePath));

            // Verify CWT claims are in the signature
            byte[] signatureBytes = File.ReadAllBytes(signaturePath);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

            bool hasClaims = message.TryGetCwtClaims(out CwtClaims? claims);
            Assert.IsTrue(hasClaims);
            Assert.IsNotNull(claims);
            Assert.AreEqual("did:example:issuer", claims.Issuer);
            Assert.AreEqual("test.subject", claims.Subject);
            Assert.AreEqual("test-audience", claims.Audience);
        }
        finally
        {
            SafeDeleteFile(signaturePath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithScittDisabled_ShouldNotIncludeCWTClaims()
    {
        // NOTE: This test verifies the new behavior where disabling SCITT compliance
        // prevents automatic addition of default CWT claims.
        
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        string signaturePath = TestSignaturePath + "_no_scitt";
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = signaturePath,
            ["pfx"] = TestCertificatePath,
            ["enable-scitt"] = "false"
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(signaturePath));

            // Verify NO CWT claims are present when SCITT is disabled
            byte[] signatureBytes = File.ReadAllBytes(signaturePath);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

            bool hasClaims = message.TryGetCwtClaims(out CwtClaims? claims);
            Assert.IsFalse(hasClaims, "Signature should NOT contain CWT claims when SCITT compliance is disabled");
            Assert.IsNull(claims, "No CWT claims should be present");
        }
        finally
        {
            SafeDeleteFile(signaturePath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithCustomCWTClaims_IntegerLabel_ShouldSucceed()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        string signaturePath = TestSignaturePath + "_custom_int";
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = signaturePath,
            ["pfx"] = TestCertificatePath,
            ["cwt-issuer"] = "test-issuer",
            ["cwt-claims"] = "100:custom-value"
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(signaturePath));

            // Verify custom claim
            byte[] signatureBytes = File.ReadAllBytes(signaturePath);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

            bool hasClaims = message.TryGetCwtClaims(out CwtClaims? claims);
            Assert.IsTrue(hasClaims);
            Assert.IsNotNull(claims);
            Assert.IsTrue(claims.CustomClaims.TryGetValue(100, out object? value));
            Assert.AreEqual("custom-value", value);
        }
        finally
        {
            SafeDeleteFile(signaturePath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithCustomCWTClaims_LongValue_ShouldSucceed()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        string signaturePath = TestSignaturePath + "_custom_long";
        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = signaturePath,
            ["pfx"] = TestCertificatePath,
            ["cwt-issuer"] = "test-issuer",
            ["cwt-claims"] = $"101:{timestamp}"
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(signaturePath));

            // Verify custom claim
            byte[] signatureBytes = File.ReadAllBytes(signaturePath);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

            bool hasClaims = message.TryGetCwtClaims(out CwtClaims? claims);
            Assert.IsTrue(hasClaims);
            Assert.IsNotNull(claims);
            Assert.IsTrue(claims.CustomClaims.ContainsKey(101));
            Assert.AreEqual(timestamp, claims.CustomClaims[101]);
        }
        finally
        {
            SafeDeleteFile(signaturePath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithCustomCWTClaims_NamedClaims_ShouldSucceed()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        string signaturePath = TestSignaturePath + "_named_claims";
        var expirationDate = DateTimeOffset.UtcNow.AddMonths(6);
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = signaturePath,
            ["pfx"] = TestCertificatePath,
            ["cwt-issuer"] = "test-issuer",
            ["cwt-claims"] = $"exp:{expirationDate:O}",
            ["cwt-claims:1"] = $"nbf:{DateTimeOffset.UtcNow.AddDays(-1):O}",
            ["cwt-claims:2"] = $"iat:{DateTimeOffset.UtcNow:O}"
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(signaturePath));

            // Verify named claims
            byte[] signatureBytes = File.ReadAllBytes(signaturePath);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

            bool hasClaims = message.TryGetCwtClaims(out CwtClaims? claims);
            Assert.IsTrue(hasClaims);
            Assert.IsNotNull(claims);
            Assert.IsNotNull(claims.ExpirationTime);
            Assert.IsNotNull(claims.NotBefore);
            Assert.IsNotNull(claims.IssuedAt);
        }
        finally
        {
            SafeDeleteFile(signaturePath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithCustomCWTClaims_InvalidFormat_ShouldFail()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["pfx"] = TestCertificatePath,
            ["cwt-issuer"] = "test-issuer",
            ["cwt-claims"] = "invalid-format-no-colon"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UnknownError, result);
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithCustomCWTClaims_UnknownName_ShouldFail()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["pfx"] = TestCertificatePath,
            ["cwt-issuer"] = "test-issuer",
            ["cwt-claims"] = "unknown:value"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UnknownError, result);
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithCWTID_ShouldSucceed()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        string signaturePath = TestSignaturePath + "_cwtid";
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = signaturePath,
            ["pfx"] = TestCertificatePath,
            ["cwt-issuer"] = "test-issuer",
            ["cwt-claims"] = "cti:test-cwt-id"
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(signaturePath));

            // Verify CWT ID claim
            byte[] signatureBytes = File.ReadAllBytes(signaturePath);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

            bool hasClaims = message.TryGetCwtClaims(out CwtClaims? claims);
            Assert.IsTrue(hasClaims);
            Assert.IsNotNull(claims);
            Assert.IsNotNull(claims.CwtId);
            CollectionAssert.AreEqual(System.Text.Encoding.UTF8.GetBytes("test-cwt-id"), claims.CwtId);
        }
        finally
        {
            SafeDeleteFile(signaturePath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithScittDisabledAndNoCwtClaims_ShouldNotIncludeAnyCwtClaims()
    {
        // Arrange - Regression test to ensure no CWT claims when SCITT disabled and no custom claims
        IndirectSignCommand command = new IndirectSignCommand();
        string signaturePath = TestSignaturePath + "_scitt_disabled_no_claims";
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = signaturePath,
            ["pfx"] = TestCertificatePath,
            ["enable-scitt"] = "false"
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(signaturePath));

            // Verify NO CWT claims whatsoever are present in the signature
            byte[] signatureBytes = File.ReadAllBytes(signaturePath);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

            bool hasClaims = message.TryGetCwtClaims(out CwtClaims? claims);
            Assert.IsFalse(hasClaims, "Signature should NOT contain any CWT claims when SCITT is disabled and no custom claims specified");
            Assert.IsNull(claims, "No CWT claims should be present in the signature");
        }
        finally
        {
            SafeDeleteFile(signaturePath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithScittDisabledButCustomCwtClaims_ShouldIncludeOnlyCustomClaims()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        string signaturePath = TestSignaturePath + "_scitt_disabled_custom_claims";
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = signaturePath,
            ["pfx"] = TestCertificatePath,
            ["enable-scitt"] = "false",
            ["cwt-issuer"] = "custom-issuer",
            ["cwt-subject"] = "custom-subject"
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(signaturePath));

            // Verify that custom CWT claims are present (user overrides are honored even with SCITT disabled)
            byte[] signatureBytes = File.ReadAllBytes(signaturePath);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

            bool hasClaims = message.TryGetCwtClaims(out CwtClaims? claims);
            Assert.IsTrue(hasClaims, "Signature should contain custom CWT claims specified by user");
            Assert.IsNotNull(claims);
            Assert.AreEqual("custom-issuer", claims!.Issuer, "Custom issuer should be present");
            Assert.AreEqual("custom-subject", claims.Subject, "Custom subject should be present");
        }
        finally
        {
            SafeDeleteFile(signaturePath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithScittEnabledDefault_ShouldIncludeDefaultCwtClaims()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        string signaturePath = TestSignaturePath + "_scitt_enabled_default";
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = signaturePath,
            ["pfx"] = TestCertificatePath
            // Note: not specifying enable-scitt, should default to true
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(signaturePath));

            // Verify default CWT claims are present
            byte[] signatureBytes = File.ReadAllBytes(signaturePath);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

            bool hasClaims = message.TryGetCwtClaims(out CwtClaims? claims);
            Assert.IsTrue(hasClaims, "Signature should contain default CWT claims when SCITT is enabled by default");
            Assert.IsNotNull(claims);
            Assert.IsNotNull(claims!.Issuer);
            Assert.IsTrue(claims.Issuer.Length > 0, "Default issuer (DID:x509) should be present");
            Assert.AreEqual("unknown.intent", claims.Subject, "Default subject should be present");
        }
        finally
        {
            SafeDeleteFile(signaturePath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithScittExplicitlyEnabled_ShouldIncludeDefaultCwtClaims()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        string signaturePath = TestSignaturePath + "_scitt_explicitly_enabled";
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = signaturePath,
            ["pfx"] = TestCertificatePath,
            ["enable-scitt"] = "true"
        });

        try
        {
            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
            Assert.IsTrue(File.Exists(signaturePath));

            // Verify default CWT claims are present
            byte[] signatureBytes = File.ReadAllBytes(signaturePath);
            CoseSign1Message message = CoseMessage.DecodeSign1(signatureBytes);

            bool hasClaims = message.TryGetCwtClaims(out CwtClaims? claims);
            Assert.IsTrue(hasClaims, "Signature should contain default CWT claims when SCITT is explicitly enabled");
            Assert.IsNotNull(claims);
            Assert.IsNotNull(claims!.Issuer);
            Assert.IsTrue(claims.Issuer.Length > 0, "Default issuer (DID:x509) should be present");
            Assert.AreEqual("unknown.intent", claims.Subject, "Default subject should be present");
        }
        finally
        {
            SafeDeleteFile(signaturePath);
        }
    }

    [TestMethod]
    public async Task IndirectSignCommand_Execute_WithInvalidSignatureVersion_ShouldFail()
    {
        // Arrange
        IndirectSignCommand command = new IndirectSignCommand();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["payload"] = TestPayloadPath,
            ["signature"] = TestSignaturePath,
            ["pfx"] = TestCertificatePath,
            ["signature-version"] = "INVALID"
        });

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }
}

