// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Security.CodeTransparency;
using System.Security.Cryptography.Cose;

namespace CoseSignTool.MST.Plugin.Tests;

/// <summary>
/// Tests for logging behavior in MstCommandBase.
/// </summary>
[TestClass]
public class MstCommandBaseLoggingTests
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
        PluginExitCode result = TestMstCommand.TestValidateCommonParameters(configuration, out int timeout, logger);

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
        PluginExitCode result = TestMstCommand.TestValidateCommonParameters(configuration, out int timeout, null);
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    [TestMethod]
    public void ValidateFilePaths_WithMissingFile_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        Dictionary<string, string> filePaths = new Dictionary<string, string>
        {
            ["Payload"] = "nonexistent-file.bin"
        };

        // Act
        PluginExitCode result = TestMstCommand.TestValidateFilePaths(filePaths, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Payload file not found")));
    }

    [TestMethod]
    public void ValidateFilePaths_WithNullLogger_DoesNotThrow()
    {
        // Arrange
        Dictionary<string, string> filePaths = new Dictionary<string, string>
        {
            ["Payload"] = "nonexistent.bin"
        };

        // Act & Assert - should not throw
        PluginExitCode result = TestMstCommand.TestValidateFilePaths(filePaths, null);
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public async Task ReadAndDecodeCoseMessage_WithInvalidData_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        string tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, new byte[] { 0x01, 0x02, 0x03 }); // Invalid COSE

        try
        {
            // Act
            (CoseSign1Message? message, _, PluginExitCode result) = 
                await TestMstCommand.TestReadAndDecodeCoseMessage(tempFile, CancellationToken.None, logger);

            // Assert
            Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
            Assert.IsNull(message);
            Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Failed to decode")));
            Assert.IsTrue(logger.LoggedExceptions.Count > 0);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    [TestMethod]
    public async Task ReadAndDecodeCoseMessage_WithNullLogger_DoesNotThrow()
    {
        // Arrange
        string tempFile = Path.GetTempFileName();
        await File.WriteAllBytesAsync(tempFile, new byte[] { 0x01, 0x02, 0x03 });

        try
        {
            // Act & Assert - should not throw
            (CoseSign1Message? message, byte[] signatureBytes, PluginExitCode result) = 
                await TestMstCommand.TestReadAndDecodeCoseMessage(tempFile, CancellationToken.None, null);
            Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
        }
        finally
        {
            File.Delete(tempFile);
        }
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
            await TestMstCommand.TestWriteJsonResult(outputPath, testData, CancellationToken.None, logger);

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
    public async Task WriteJsonResult_WithNullLogger_DoesNotThrow()
    {
        // Arrange
        string outputPath = Path.GetTempFileName() + ".json";
        var testData = new { Test = "Value" };

        try
        {
            // Act & Assert - should not throw
            await TestMstCommand.TestWriteJsonResult(outputPath, testData, CancellationToken.None, null);
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
        PluginExitCode result = TestMstCommand.TestHandleCommonException(exception, configuration, CancellationToken.None, logger);

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
        PluginExitCode result = TestMstCommand.TestHandleCommonException(exception, configuration, CancellationToken.None, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("File not found")));
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
        PluginExitCode result = TestMstCommand.TestHandleCommonException(exception, configuration, cts.Token, logger);

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
            ["timeout"] = "45"
        });
        OperationCanceledException exception = new OperationCanceledException();

        // Act
        PluginExitCode result = TestMstCommand.TestHandleCommonException(exception, configuration, CancellationToken.None, logger);

        // Assert
        Assert.AreEqual(PluginExitCode.UnknownError, result);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("timed out after 45 seconds")));
    }

    [TestMethod]
    public void HandleCommonException_WithGenericException_LogsError()
    {
        // Arrange
        MockLogger logger = new MockLogger();
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());
        Exception exception = new Exception("Generic error message");

        // Act
        PluginExitCode result = TestMstCommand.TestHandleCommonException(exception, configuration, CancellationToken.None, logger);

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
        PluginExitCode result = TestMstCommand.TestHandleCommonException(exception, configuration, CancellationToken.None, null);
        Assert.AreEqual(PluginExitCode.UnknownError, result);
    }

    [TestMethod]
    public void CreateTimeoutCancellationToken_CreatesValidToken()
    {
        // Arrange & Act
        using CancellationTokenSource result = TestMstCommand.TestCreateTimeoutCancellationToken(5, CancellationToken.None);

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
        using CancellationTokenSource result = TestMstCommand.TestCreateTimeoutCancellationToken(5, cts.Token);

        // Assert
        Assert.IsTrue(result.IsCancellationRequested);
    }

    [TestMethod]
    public void PrintOperationStatus_WithAllParameters_LogsCorrectly()
    {
        // Arrange
        TestMstCommand command = new TestMstCommand();
        MockLogger logger = new MockLogger { Level = LogLevel.Verbose };
        command.SetLogger(logger);

        // Act
        command.TestPrintOperationStatus("Testing", "https://test.com", "/path/payload", "/path/signature", 1024, "Extra info");

        // Assert
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Testing")));
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("https://test.com")));
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("/path/payload")));
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("/path/signature")));
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("1024")));
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Extra info")));
    }

    [TestMethod]
    public void PrintOperationStatus_WithoutAdditionalInfo_LogsCorrectly()
    {
        // Arrange
        TestMstCommand command = new TestMstCommand();
        MockLogger logger = new MockLogger { Level = LogLevel.Verbose };
        command.SetLogger(logger);

        // Act
        command.TestPrintOperationStatus("Testing", "https://test.com", "/path/payload", "/path/signature", 512, null);

        // Assert
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("Testing")));
        Assert.AreEqual(4, logger.LoggedMessages.Count(m => m.Message.Contains("VERBOSE") || m.Message.Contains("INFO")));
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
        string? result = TestMstCommand.TestGetOptionalValue(configuration, "test-key");

        // Assert
        Assert.AreEqual("test-value", result);
    }

    [TestMethod]
    public void GetOptionalValue_WithoutValue_ReturnsDefault()
    {
        // Arrange
        IConfiguration configuration = CreateConfiguration(new Dictionary<string, string?>());

        // Act
        string? result = TestMstCommand.TestGetOptionalValue(configuration, "missing-key", "default-value");

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
        string result = TestMstCommand.TestGetRequiredValue(configuration, "test-key");

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
            TestMstCommand.TestGetRequiredValue(configuration, "missing-key"));
    }

    private static IConfiguration CreateConfiguration(Dictionary<string, string?> values)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(values!)
            .Build();
    }

    /// <summary>
    /// Test wrapper to access protected static methods in MstCommandBase.
    /// </summary>
    private class TestMstCommand : MstCommandBase
    {
        public override string Name => "test";
        public override string Description => "Test";
        public override string Usage => "Test";
        public override IDictionary<string, string> Options => new Dictionary<string, string>();

        protected override string GetExamples() => "Test";

        protected override void AddAdditionalFileValidation(Dictionary<string, string> requiredFiles, IConfiguration configuration) { }

        protected override Task<(PluginExitCode exitCode, object? result)> ExecuteSpecificOperation(
            CodeTransparencyClient client, CoseSign1Message message, byte[] signatureBytes,
            string endpoint, string payloadPath, string signaturePath,
            IConfiguration configuration, CancellationToken cancellationToken)
        {
            return Task.FromResult<(PluginExitCode, object?)>((PluginExitCode.Success, null));
        }

        public static PluginExitCode TestValidateCommonParameters(IConfiguration configuration, out int timeoutSeconds, IPluginLogger? logger)
            => ValidateCommonParameters(configuration, out timeoutSeconds, logger);

        public static PluginExitCode TestValidateFilePaths(Dictionary<string, string> filePaths, IPluginLogger? logger)
            => ValidateFilePaths(filePaths, logger);

        public static Task<(CoseSign1Message? message, byte[] signatureBytes, PluginExitCode result)> TestReadAndDecodeCoseMessage(
            string signaturePath, CancellationToken cancellationToken, IPluginLogger? logger)
            => ReadAndDecodeCoseMessage(signaturePath, cancellationToken, logger);

        public static Task TestWriteJsonResult(string outputPath, object result, CancellationToken cancellationToken, IPluginLogger? logger)
            => WriteJsonResult(outputPath, result, cancellationToken, logger);

        public static PluginExitCode TestHandleCommonException(Exception ex, IConfiguration configuration, CancellationToken cancellationToken, IPluginLogger? logger)
            => HandleCommonException(ex, configuration, cancellationToken, logger);

        public static CancellationTokenSource TestCreateTimeoutCancellationToken(int timeoutSeconds, CancellationToken cancellationToken)
            => CreateTimeoutCancellationToken(timeoutSeconds, cancellationToken);

        public void TestPrintOperationStatus(string operation, string endpoint, string payloadPath, string signaturePath, int signatureSize, string? additionalInfo)
            => PrintOperationStatus(operation, endpoint, payloadPath, signaturePath, signatureSize, additionalInfo);

        public static string? TestGetOptionalValue(IConfiguration configuration, string key, string? defaultValue = null)
            => GetOptionalValue(configuration, key, defaultValue);

        public static string TestGetRequiredValue(IConfiguration configuration, string key)
            => GetRequiredValue(configuration, key);
    }
}

