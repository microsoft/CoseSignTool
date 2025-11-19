// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Azure.Security.CodeTransparency;
using System.Security.Cryptography.Cose;

namespace CoseSignTool.CTS.Plugin.Tests;

/// <summary>
/// Tests for VerifyCommand logging behavior.
/// </summary>
[TestClass]
public class VerifyCommandLoggingTests
{
    private class MockLogger : IPluginLogger
    {
        public List<(LogLevel Level, string Message)> LoggedMessages { get; } = new();
        public List<(Exception Exception, string? Message)> LoggedExceptions { get; } = new();
        public LogLevel Level { get; set; } = LogLevel.Normal;

        public void LogError(string message) => LoggedMessages.Add((LogLevel.Normal, $"ERROR: {message}"));
        public void LogWarning(string message) => LoggedMessages.Add((LogLevel.Normal, $"WARNING: {message}"));
        public void LogInformation(string message) => LoggedMessages.Add((LogLevel.Normal, $"INFO: {message}"));
        public void LogVerbose(string message)
        {
            if (Level == LogLevel.Verbose)
            {
                LoggedMessages.Add((LogLevel.Verbose, $"VERBOSE: {message}"));
            }
        }
        public void LogException(Exception ex, string? message = null) => LoggedExceptions.Add((ex, message));
    }

    [TestMethod]
    public void VerifyCommand_ParseVerificationOptions_WithInvalidAuthorizedBehavior_LogsWarning()
    {
        // Arrange
        TestVerifyCommand command = new TestVerifyCommand();
        MockLogger logger = new MockLogger();
        command.SetLogger(logger);
        
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["authorized-receipt-behavior"] = "InvalidBehavior"
            }!)
            .Build();

        // Act
        CodeTransparencyVerificationOptions? options = command.TestParseVerificationOptions(configuration);

        // Assert
        Assert.IsNotNull(options);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("WARNING") && m.Message.Contains("Invalid authorized-receipt-behavior")));
    }

    [TestMethod]
    public void VerifyCommand_ParseVerificationOptions_WithInvalidUnauthorizedBehavior_LogsWarning()
    {
        // Arrange
        TestVerifyCommand command = new TestVerifyCommand();
        MockLogger logger = new MockLogger();
        command.SetLogger(logger);
        
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["unauthorized-receipt-behavior"] = "InvalidBehavior"
            }!)
            .Build();

        // Act
        CodeTransparencyVerificationOptions? options = command.TestParseVerificationOptions(configuration);

        // Assert
        Assert.IsNotNull(options);
        Assert.IsTrue(logger.LoggedMessages.Any(m => m.Message.Contains("WARNING") && m.Message.Contains("Invalid unauthorized-receipt-behavior")));
    }

    [TestMethod]
    public void VerifyCommand_ParseVerificationOptions_WithValidBehaviors_DoesNotLogWarning()
    {
        // Arrange
        TestVerifyCommand command = new TestVerifyCommand();
        MockLogger logger = new MockLogger();
        command.SetLogger(logger);
        
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["authorized-receipt-behavior"] = "VerifyAnyMatching",
                ["unauthorized-receipt-behavior"] = "IgnoreAll"
            }!)
            .Build();

        // Act
        CodeTransparencyVerificationOptions? options = command.TestParseVerificationOptions(configuration);

        // Assert
        Assert.IsNotNull(options);
        Assert.IsFalse(logger.LoggedMessages.Any(m => m.Message.Contains("WARNING")));
        Assert.AreEqual(AuthorizedReceiptBehavior.VerifyAnyMatching, options.AuthorizedReceiptBehavior);
        Assert.AreEqual(UnauthorizedReceiptBehavior.IgnoreAll, options.UnauthorizedReceiptBehavior);
    }

    [TestMethod]
    public void VerifyCommand_ParseVerificationOptions_WithAuthorizedDomains_ParsesCorrectly()
    {
        // Arrange
        TestVerifyCommand command = new TestVerifyCommand();
        
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["authorized-domains"] = "domain1.com,domain2.com,domain3.com"
            }!)
            .Build();

        // Act
        CodeTransparencyVerificationOptions? options = command.TestParseVerificationOptions(configuration);

        // Assert
        Assert.IsNotNull(options);
        Assert.AreEqual(3, options.AuthorizedDomains.Count);
        Assert.IsTrue(options.AuthorizedDomains.Contains("domain1.com"));
        Assert.IsTrue(options.AuthorizedDomains.Contains("domain2.com"));
        Assert.IsTrue(options.AuthorizedDomains.Contains("domain3.com"));
    }

    [TestMethod]
    public void VerifyCommand_ParseVerificationOptions_WithNoOptions_ReturnsNull()
    {
        // Arrange
        TestVerifyCommand command = new TestVerifyCommand();
        
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();

        // Act
        CodeTransparencyVerificationOptions? options = command.TestParseVerificationOptions(configuration);

        // Assert
        Assert.IsNull(options);
    }

    private class TestVerifyCommand : VerifyCommand
    {
        public CodeTransparencyVerificationOptions? TestParseVerificationOptions(IConfiguration configuration)
        {
            // Use reflection to call private method
            var method = typeof(VerifyCommand).GetMethod("ParseVerificationOptions", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            return (CodeTransparencyVerificationOptions?)method?.Invoke(this, new object[] { configuration });
        }
    }
}
