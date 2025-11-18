// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.IndirectSignature.Plugin.Tests;

/// <summary>
/// Tests for logging behavior in IndirectSignatureCommandBase.
/// </summary>
[TestClass]
public class IndirectSignatureCommandBaseLoggingTests
{
    /// <summary>
    /// Mock logger to capture logging calls.
    /// </summary>
    private class MockLogger : IPluginLogger
    {
        public List<(LogLevel Level, string Message)> LoggedMessages { get; } = new();
        public List<(Exception Exception, string? Message)> LoggedExceptions { get; } = new();
        public LogLevel Level { get; set; } = LogLevel.Normal;

        public void LogError(string message)
        {
            LoggedMessages.Add((LogLevel.Normal, $"ERROR: {message}"));
        }

        public void LogWarning(string message)
        {
            LoggedMessages.Add((LogLevel.Normal, $"WARNING: {message}"));
        }

        public void LogInformation(string message)
        {
            LoggedMessages.Add((LogLevel.Normal, $"INFO: {message}"));
        }

        public void LogVerbose(string message)
        {
            if (Level == LogLevel.Verbose)
            {
                LoggedMessages.Add((LogLevel.Verbose, $"VERBOSE: {message}"));
            }
        }

        public void LogException(Exception ex, string? message = null)
        {
            LoggedExceptions.Add((ex, message));
        }
    }

    [TestMethod]
    public void ValidateCommonParameters_WithInvalidTimeout_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["timeout"] = "invalid"
        });

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.ValidateCommonParameters(configuration, out int timeout, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Invalid timeout value")));
    }

    [TestMethod]
    public void ValidateCommonParameters_WithNullLogger_DoesNotThrow()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["timeout"] = "invalid"
        });

        // Act & Assert - should not throw
        PluginExitCode result = IndirectSignatureCommandBase.ValidateCommonParameters(configuration, out int timeout, null);
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    [TestMethod]
    public void ValidateFilePaths_WithMissingFile_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        Dictionary<string, string?> filePaths = new Dictionary<string, string?>
        {
            ["Payload"] = "nonexistent-file.bin"
        };

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.ValidateFilePaths(filePaths, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Payload file not found")));
    }

    [TestMethod]
    public void ValidateFilePaths_WithEmptyPath_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        Dictionary<string, string?> filePaths = new Dictionary<string, string?>
        {
            ["Payload"] = ""
        };

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.ValidateFilePaths(filePaths, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Payload file path is required")));
    }

    [TestMethod]
    public void ValidateFilePaths_WithNullLogger_DoesNotThrow()
    {
        // Arrange
        Dictionary<string, string?> filePaths = new Dictionary<string, string?>
        {
            ["Payload"] = "nonexistent.bin"
        };

        // Act & Assert - should not throw
        PluginExitCode result = IndirectSignatureCommandBase.ValidateFilePaths(filePaths, null);
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public void LoadSigningCertificate_WithMissingPfx_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["pfx"] = "nonexistent.pfx"
        });

        // Act
        (X509Certificate2? certificate, List<X509Certificate2>? additionalCertificates, PluginExitCode result) = 
            IndirectSignatureCommandBase.LoadSigningCertificate(configuration, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
        Assert.IsNull(certificate);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Certificate file not found")));
    }

    [TestMethod]
    public void LoadSigningCertificate_WithEmptyPfx_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        string pfxPath = Path.GetTempFileName();
        File.WriteAllBytes(pfxPath, Array.Empty<byte>()); // Empty file

        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["pfx"] = pfxPath
        });

        try
        {
            // Act
            (X509Certificate2? certificate, List<X509Certificate2>? additionalCertificates, PluginExitCode result) = 
                IndirectSignatureCommandBase.LoadSigningCertificate(configuration, logger);

            // Assert
            Assert.AreEqual(PluginExitCode.CertificateLoadFailure, result);
            Assert.IsNull(certificate);
            Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("ERROR:")));
        }
        finally
        {
            File.Delete(pfxPath);
        }
    }

    [TestMethod]
    public void LoadSigningCertificate_WithInvalidStoreLocation_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["thumbprint"] = "1234567890abcdef",
            ["store-location"] = "InvalidLocation"
        });

        // Act
        (X509Certificate2? certificate, List<X509Certificate2>? additionalCertificates, PluginExitCode result) = 
            IndirectSignatureCommandBase.LoadSigningCertificate(configuration, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
        Assert.IsNull(certificate);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Invalid store location")));
    }

    [TestMethod]
    public void LoadSigningCertificate_WithNonexistentThumbprint_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["thumbprint"] = "0000000000000000000000000000000000000000",
            ["store-name"] = "My",
            ["store-location"] = "CurrentUser"
        });

        // Act
        (X509Certificate2? certificate, List<X509Certificate2>? additionalCertificates, PluginExitCode result) = 
            IndirectSignatureCommandBase.LoadSigningCertificate(configuration, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
        Assert.IsNull(certificate);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("not found in store")));
    }

    [TestMethod]
    public void LoadSigningCertificate_WithNullLogger_DoesNotThrow()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["pfx"] = "nonexistent.pfx"
        });

        // Act & Assert - should not throw
        (X509Certificate2? certificate, List<X509Certificate2>? additionalCertificates, PluginExitCode result) = 
            IndirectSignatureCommandBase.LoadSigningCertificate(configuration, null);
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public async Task WriteJsonResult_WithValidData_LogsInformation()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        string outputPath = Path.GetTempFileName() + ".json";
        var testData = new { Test = "Value" };

        try
        {
            // Act
            await IndirectSignatureCommandBase.WriteJsonResult(outputPath, testData, CancellationToken.None, logger);

            // Assert
            Assert.IsTrue(File.Exists(outputPath));
            Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Result written to")));
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
    public async Task WriteJsonResult_WithWarningPayload_LogsWarning()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        string outputPath = Path.GetTempFileName() + ".json";
        var testData = new { Warning = "Test warning message" };

        try
        {
            // Act
            await IndirectSignatureCommandBase.WriteJsonResult(outputPath, testData, CancellationToken.None, logger);

            // Assert
            Assert.IsTrue(File.Exists(outputPath));
            string content = await File.ReadAllTextAsync(outputPath);
            Assert.IsTrue(content.Contains("warning"));
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
    public async Task WriteJsonResult_WithNullLogger_DoesNotThrow()
    {
        // Arrange
        string outputPath = Path.GetTempFileName() + ".json";
        var testData = new { Test = "Value" };

        try
        {
            // Act & Assert - should not throw
            await IndirectSignatureCommandBase.WriteJsonResult(outputPath, testData, CancellationToken.None, null);
            Assert.IsTrue(File.Exists(outputPath));
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
    public void HandleCommonException_WithArgumentNullException_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());
        ArgumentNullException exception = new ArgumentNullException("testParam");

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.HandleCommonException(exception, configuration, CancellationToken.None, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Missing required argument")));
    }

    [TestMethod]
    public void HandleCommonException_WithFileNotFoundException_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());
        FileNotFoundException exception = new FileNotFoundException("Test file not found");

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.HandleCommonException(exception, configuration, CancellationToken.None, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("File not found")));
    }

    [TestMethod]
    public void HandleCommonException_WithArgumentException_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());
        ArgumentException exception = new ArgumentException("Invalid argument");

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.HandleCommonException(exception, configuration, CancellationToken.None, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Invalid argument")));
    }

    [TestMethod]
    public void HandleCommonException_WithCryptographicException_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());
        CryptographicException exception = new CryptographicException("Crypto error");

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.HandleCommonException(exception, configuration, CancellationToken.None, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.CertificateLoadFailure, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Crypto error")));
    }

    [TestMethod]
    public void HandleCommonException_WithCancellation_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());
        CancellationTokenSource cts = new CancellationTokenSource();
        cts.Cancel();
        OperationCanceledException exception = new OperationCanceledException(cts.Token);

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.HandleCommonException(exception, configuration, cts.Token, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.UnknownError, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Operation was cancelled")));
    }

    [TestMethod]
    public void HandleCommonException_WithTimeout_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["timeout"] = "60"
        });
        OperationCanceledException exception = new OperationCanceledException();

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.HandleCommonException(exception, configuration, CancellationToken.None, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.UnknownError, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("timed out after 60 seconds")));
    }

    [TestMethod]
    public void HandleCommonException_WithGenericException_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());
        Exception exception = new Exception("Generic error message");

        // Act
        PluginExitCode result = IndirectSignatureCommandBase.HandleCommonException(exception, configuration, CancellationToken.None, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.UnknownError, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Generic error message")));
    }

    [TestMethod]
    public void HandleCommonException_WithNullLogger_DoesNotThrow()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());
        Exception exception = new Exception("Test error");

        // Act & Assert - should not throw
        PluginExitCode result = IndirectSignatureCommandBase.HandleCommonException(exception, configuration, CancellationToken.None, null);
        Assert.AreEqual(PluginExitCode.UnknownError, result);
    }

    [TestMethod]
    public void CreateTimeoutCancellationToken_CreatesValidToken()
    {
        // Arrange & Act
        using CancellationTokenSource result = IndirectSignatureCommandBase.CreateTimeoutCancellationToken(5, CancellationToken.None);

        // Assert
        Assert.IsNotNull(result);
        Assert.IsFalse(result.IsCancellationRequested);
    }

    [TestMethod]
    public void CreateTimeoutCancellationToken_CombinesWithCancellationToken()
    {
        // Arrange
        using CancellationTokenSource cts = new CancellationTokenSource();
        cts.Cancel();

        // Act
        using CancellationTokenSource result = IndirectSignatureCommandBase.CreateTimeoutCancellationToken(5, cts.Token);

        // Assert
        Assert.IsTrue(result.IsCancellationRequested);
    }

    [TestMethod]
    public void GetOptionalValue_WithValue_ReturnsValue()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["test-key"] = "test-value"
        });

        // Act
        string? result = TestCommand.TestGetOptionalValue(configuration, "test-key");

        // Assert
        Assert.AreEqual("test-value", result);
    }

    [TestMethod]
    public void GetOptionalValue_WithoutValue_ReturnsDefault()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());

        // Act
        string? result = TestCommand.TestGetOptionalValue(configuration, "missing-key", "default-value");

        // Assert
        Assert.AreEqual("default-value", result);
    }

    [TestMethod]
    public void GetRequiredValue_WithValue_ReturnsValue()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>
        {
            ["test-key"] = "test-value"
        });

        // Act
        string result = TestCommand.TestGetRequiredValue(configuration, "test-key");

        // Assert
        Assert.AreEqual("test-value", result);
    }

    [TestMethod]
    public void GetRequiredValue_WithoutValue_ThrowsArgumentNullException()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());

        // Act & Assert
        Assert.ThrowsException<ArgumentNullException>(() => 
            TestCommand.TestGetRequiredValue(configuration, "missing-key"));
    }

    // Test helper class
    private class TestCommand : IndirectSignatureCommandBase
    {
        public override string Name => "test";
        public override string Description => "Test command";
        public override string Usage => "test usage";
        public override IDictionary<string, string> Options => new Dictionary<string, string>();

        protected override string GetExamples() => "Test examples";

        public override Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(PluginExitCode.Success);
        }

        public static string? TestGetOptionalValue(IConfiguration configuration, string key, string? defaultValue = null)
            => GetOptionalValue(configuration, key, defaultValue);

        public static string TestGetRequiredValue(IConfiguration configuration, string key)
            => GetRequiredValue(configuration, key);
    }

    private static IConfiguration CreateConfiguration(Dictionary<string, string?> values)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(values!)
            .Build();
    }
}
