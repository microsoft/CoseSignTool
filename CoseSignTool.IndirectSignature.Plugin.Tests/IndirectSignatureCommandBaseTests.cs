// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.IndirectSignature.Plugin.Tests;

[TestClass]
public class IndirectSignatureCommandBaseTests
{
    [TestInitialize]
    public void TestInitialize()
    {
        // Test setup - no fields needed as we're testing static methods
    }

    [TestMethod]
    public void ValidateCommonParameters_WithValidTimeout_ShouldSucceed()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["timeout"] = "30"
        });

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.ValidateCommonParameters(configuration, out int timeout);

        // Assert
        Assert.AreEqual(PluginExitCode.Success, result);
        Assert.AreEqual(30, timeout);
    }

    [TestMethod]
    public void ValidateCommonParameters_WithInvalidTimeout_ShouldFail()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["timeout"] = "invalid"
        });

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.ValidateCommonParameters(configuration, out int timeout);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
        Assert.AreEqual(0, timeout);
    }

    [TestMethod]
    public void ValidateCommonParameters_WithNegativeTimeout_ShouldFail()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["timeout"] = "-5"
        });

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.ValidateCommonParameters(configuration, out int timeout);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    [TestMethod]
    public void ValidateCommonParameters_WithDefaultTimeout_ShouldSucceed()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.ValidateCommonParameters(configuration, out int timeout);

        // Assert
        Assert.AreEqual(PluginExitCode.Success, result);
        Assert.AreEqual(30, timeout);
    }

    [TestMethod]
    public void ValidateFilePaths_WithExistingFiles_ShouldSucceed()
    {
        // Arrange
        string testFile1 = Path.GetTempFileName();
        string testFile2 = Path.GetTempFileName();
        File.WriteAllText(testFile1, "test");
        File.WriteAllText(testFile2, "test");

        Dictionary<string, string?> filePaths = new Dictionary<string, string?>
        {
            ["File1"] = testFile1,
            ["File2"] = testFile2
        };

        try
        {
            // Act
            PluginExitCode result = IndirectSignatureCommandBase.ValidateFilePaths(filePaths);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result);
        }
        finally
        {
            File.Delete(testFile1);
            File.Delete(testFile2);
        }
    }

    [TestMethod]
    public void ValidateFilePaths_WithNonExistentFile_ShouldFail()
    {
        // Arrange
        Dictionary<string, string?> filePaths = new Dictionary<string, string?>
        {
            ["TestFile"] = "nonexistent-file.txt"
        };

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.ValidateFilePaths(filePaths);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public void ValidateFilePaths_WithEmptyPath_ShouldFail()
    {
        // Arrange
        Dictionary<string, string?> filePaths = new Dictionary<string, string?>
        {
            ["TestFile"] = ""
        };

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.ValidateFilePaths(filePaths);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public void LoadSigningCertificate_WithValidPfx_ShouldSucceed()
    {
        // Arrange
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        string pfxPath = Path.GetTempFileName() + ".pfx";
        File.WriteAllBytes(pfxPath, cert.Export(X509ContentType.Pkcs12));

        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["pfx"] = pfxPath
        });

        try
        {
            // Act
            (X509Certificate2? certificate, List<X509Certificate2>? additionalCertificates, PluginExitCode result) result = IndirectSignatureCommandBase.LoadSigningCertificate(configuration);

            // Assert
            Assert.AreEqual(PluginExitCode.Success, result.result);
            Assert.IsNotNull(result.certificate);
            Assert.IsTrue(result.certificate.HasPrivateKey);
        }
        finally
        {
            File.Delete(pfxPath);
        }
    }

    [TestMethod]
    public void LoadSigningCertificate_WithNonExistentPfx_ShouldFail()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["pfx"] = "nonexistent.pfx"
        });

        // Act
        (X509Certificate2? certificate, List<X509Certificate2>? additionalCertificates, PluginExitCode result) result = IndirectSignatureCommandBase.LoadSigningCertificate(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result.result);
        Assert.IsNull(result.certificate);
    }

    [TestMethod]
    public void LoadSigningCertificate_WithoutCertificateOptions_ShouldFail()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());

        // Act
        (X509Certificate2? certificate, List<X509Certificate2>? additionalCertificates, PluginExitCode result) result = IndirectSignatureCommandBase.LoadSigningCertificate(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result.result);
        Assert.IsNull(result.certificate);
    }

    [TestMethod]
    public void ParseHashAlgorithm_WithValidAlgorithms_ShouldSucceed()
    {
        // Test each supported algorithm
        string[] algorithms = new[] { "SHA256", "SHA384", "SHA512" };

        foreach (string? algorithm in algorithms)
        {
            // Arrange
            IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
            {
                ["hash-algorithm"] = algorithm
            });

            // Act
            HashAlgorithmName result = IndirectSignatureCommandBase.ParseHashAlgorithm(configuration);

            // Assert
            Assert.AreEqual(algorithm, result.Name);
        }
    }

    [TestMethod]
    public void ParseHashAlgorithm_WithDefault_ShouldReturnSHA256()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());

        // Act
        HashAlgorithmName result = IndirectSignatureCommandBase.ParseHashAlgorithm(configuration);

        // Assert
        Assert.AreEqual("SHA256", result.Name);
    }

    [TestMethod]
    public void ParseHashAlgorithm_WithInvalidAlgorithm_ShouldThrow()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["hash-algorithm"] = "INVALID"
        });

        // Act & Assert
        Assert.ThrowsException<ArgumentException>(() => 
            IndirectSignatureCommandBase.ParseHashAlgorithm(configuration));
    }

    [TestMethod]
    public void ParseSignatureVersion_WithValidVersions_ShouldSucceed()
    {
        // Arrange & Act & Assert
        IConfiguration configuration1 = CreateConfiguration(new Dictionary<string, string?>
        {
            ["signature-version"] = "CoseHashEnvelope"
        });
        IndirectSignatureFactory.IndirectSignatureVersion result1 = IndirectSignatureCommandBase.ParseSignatureVersion(configuration1);
        Assert.AreEqual(IndirectSignatureFactory.IndirectSignatureVersion.CoseHashEnvelope, result1);

        IConfiguration configuration2 = CreateConfiguration(new Dictionary<string, string?>());
        IndirectSignatureFactory.IndirectSignatureVersion result2 = IndirectSignatureCommandBase.ParseSignatureVersion(configuration2);
        Assert.AreEqual(IndirectSignatureFactory.IndirectSignatureVersion.CoseHashEnvelope, result2);
    }

    [TestMethod]
    public void ParseSignatureVersion_WithInvalidVersion_ShouldThrow()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["signature-version"] = "INVALID"
        });

        // Act & Assert
        Assert.ThrowsException<ArgumentException>(() => 
            IndirectSignatureCommandBase.ParseSignatureVersion(configuration));
    }

    [TestMethod]
    public void CreateTimeoutCancellationToken_ShouldCreateValidToken()
    {
        // Arrange
        using CancellationTokenSource originalToken = new CancellationTokenSource();

        // Act
        using CancellationTokenSource result = IndirectSignatureCommandBase.CreateTimeoutCancellationToken(1, originalToken.Token);

        // Assert
        Assert.IsNotNull(result);
        Assert.IsNotNull(result.Token);
        Assert.IsFalse(result.Token.IsCancellationRequested);
    }

    [TestMethod]
    public async Task WriteJsonResult_WithValidData_ShouldWriteFile()
    {
        // Arrange
        string outputPath = Path.GetTempFileName() + ".json";
        var testObject = new { Test = "Value", Number = 123 };

        try
        {
            // Act
            await IndirectSignatureCommandBase.WriteJsonResult(outputPath, testObject, CancellationToken.None);

            // Assert
            Assert.IsTrue(File.Exists(outputPath));
            string content = File.ReadAllText(outputPath);
            Assert.IsTrue(content.Contains("\"test\": \"Value\""));
            Assert.IsTrue(content.Contains("\"number\": 123"));
        }
        finally
        {
            if (File.Exists(outputPath))
            {
                File.Delete(outputPath);
            }
        }
    }

    [TestMethod]
    public void HandleCommonException_WithDifferentExceptions_ShouldReturnCorrectCodes()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());

        // Test ArgumentNullException
        ArgumentNullException argNullEx = new ArgumentNullException("testParam");
        PluginExitCode result1 = IndirectSignatureCommandBase.HandleCommonException(argNullEx, configuration, CancellationToken.None);
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result1);

        // Test FileNotFoundException
        FileNotFoundException fileNotFoundEx = new FileNotFoundException("File not found");
        PluginExitCode result2 = IndirectSignatureCommandBase.HandleCommonException(fileNotFoundEx, configuration, CancellationToken.None);
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result2);

        // Test ArgumentException
        ArgumentException argEx = new ArgumentException("Invalid argument");
        PluginExitCode result3 = IndirectSignatureCommandBase.HandleCommonException(argEx, configuration, CancellationToken.None);
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result3);

        // Test CryptographicException
        CryptographicException cryptoEx = new CryptographicException("Crypto error");
        PluginExitCode result4 = IndirectSignatureCommandBase.HandleCommonException(cryptoEx, configuration, CancellationToken.None);
        Assert.AreEqual(PluginExitCode.CertificateLoadFailure, result4);

        // Test generic Exception
        Exception genericEx = new Exception("Generic error");
        PluginExitCode result5 = IndirectSignatureCommandBase.HandleCommonException(genericEx, configuration, CancellationToken.None);
        Assert.AreEqual(PluginExitCode.UnknownError, result5);
    }

    private static IConfiguration CreateConfiguration(Dictionary<string, string?> values)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(values!)
            .Build();
    }

    /// <summary>
    /// Test implementation of IndirectSignatureCommandBase for testing protected methods.
    /// </summary>
    private class TestIndirectSignatureCommand : IndirectSignatureCommandBase
    {
        public override string Name => "test-command";
        public override string Description => "Test command";
        public override string Usage => "Test usage";
        public override IDictionary<string, string> Options => new Dictionary<string, string?>();

        public override Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(PluginExitCode.Success);
        }

        protected override string GetExamples()
        {
            return "Test examples";
        }
    }

    [TestMethod]
    public async Task WriteJsonResult_ShouldCreateValidJsonFile()
    {
        // Arrange
        TestCommand command = new TestCommand();
        string outputPath = Path.GetTempFileName() + ".json";
        object testResult = new
        {
            Operation = "Test",
            Success = true,
            Data = new
            {
                TestValue = 42,
                TestString = "Hello World",
                TestArray = new[] { 1, 2, 3 }
            }
        };

        try
        {
            // Act
            await command.PublicWriteJsonResult(outputPath, testResult, CancellationToken.None);

            // Assert
            Assert.IsTrue(File.Exists(outputPath));
            
            string jsonContent = File.ReadAllText(outputPath);
            JsonDocument jsonDoc = JsonDocument.Parse(jsonContent);
            JsonElement root = jsonDoc.RootElement;

            Assert.IsTrue(root.TryGetProperty("operation", out JsonElement operation));
            Assert.AreEqual("Test", operation.GetString());

            Assert.IsTrue(root.TryGetProperty("success", out JsonElement success));
            Assert.IsTrue(success.GetBoolean());

            Assert.IsTrue(root.TryGetProperty("data", out JsonElement data));
            Assert.IsTrue(data.TryGetProperty("testValue", out JsonElement testValue));
            Assert.AreEqual(42, testValue.GetInt32());
        }
        finally
        {
            if (File.Exists(outputPath))
            {
                File.Delete(outputPath);
            }
        }
    }

    [TestMethod]
    public async Task WriteJsonResult_WithJsonElement_ShouldPreserveStructure()
    {
        // Arrange
        TestCommand command = new TestCommand();
        string outputPath = Path.GetTempFileName() + ".json";
        
        object originalData = new
        {
            Operation = "TestWithJsonElement",
            Timestamp = DateTime.UtcNow,
            Numbers = new[] { 1, 2, 3, 4, 5 },
            Nested = new
            {
                Level1 = new
                {
                    Level2 = "Deep value"
                }
            }
        };

        // Convert to JsonElement to simulate our new strongly-typed approach
        JsonElement jsonElement = JsonSerializer.SerializeToElement(originalData);

        object outputResult = new
        {
            Success = true,
            Result = jsonElement
        };

        try
        {
            // Act
            await command.PublicWriteJsonResult(outputPath, outputResult, CancellationToken.None);

            // Assert
            Assert.IsTrue(File.Exists(outputPath));
            
            string jsonContent = File.ReadAllText(outputPath);
            JsonDocument jsonDoc = JsonDocument.Parse(jsonContent);
            JsonElement root = jsonDoc.RootElement;

            Assert.IsTrue(root.TryGetProperty("success", out JsonElement success));
            Assert.IsTrue(success.GetBoolean());

            Assert.IsTrue(root.TryGetProperty("result", out JsonElement result));
            Assert.IsTrue(result.TryGetProperty("Operation", out JsonElement operation));
            Assert.AreEqual("TestWithJsonElement", operation.GetString());

            Assert.IsTrue(result.TryGetProperty("Nested", out JsonElement nested));
            Assert.IsTrue(nested.TryGetProperty("Level1", out JsonElement level1));
            Assert.IsTrue(level1.TryGetProperty("Level2", out JsonElement level2));
            Assert.AreEqual("Deep value", level2.GetString());
        }
        finally
        {
            if (File.Exists(outputPath))
            {
                File.Delete(outputPath);
            }
        }
    }

    // Helper class to test protected methods
    private class TestCommand : IndirectSignatureCommandBase
    {
        public override string Name => "test";
        public override string Description => "Test command";
        public override IDictionary<string, string> Options => new Dictionary<string, string>();
        public override string Usage => "test usage";

        public async Task PublicWriteJsonResult(string outputPath, object result, CancellationToken cancellationToken)
        {
            await WriteJsonResult(outputPath, result, cancellationToken);
        }

        public override Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(PluginExitCode.Success);
        }

        protected override string GetExamples()
        {
            return "Test examples";
        }
    }
}
