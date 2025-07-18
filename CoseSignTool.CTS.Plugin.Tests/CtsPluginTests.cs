// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.CTS.Plugin.Tests;

/// <summary>
/// Tests for the AzureCtsPlugin class.
/// </summary>
[TestClass]
public class AzureCtsPluginTests
{
    [TestMethod]
    public void AzureCtsPlugin_Properties_ReturnCorrectValues()
    {
        // Arrange & Act
        var plugin = new AzureCtsPlugin();

        // Assert
        Assert.AreEqual("Azure Code Transparency Service", plugin.Name);
        Assert.AreEqual("1.0.0.0", plugin.Version);
        Assert.AreEqual("Provides Azure Code Transparency Service integration for registering and verifying COSE Sign1 messages.", plugin.Description);
        Assert.AreEqual(2, plugin.Commands.Count());
        
        var commandNames = plugin.Commands.Select(c => c.Name).ToArray();
        Assert.IsTrue(commandNames.Contains("cts_register"));
        Assert.IsTrue(commandNames.Contains("cts_verify"));
    }

    [TestMethod]
    public void AzureCtsPlugin_Initialize_DoesNotThrow()
    {
        // Arrange
        var plugin = new AzureCtsPlugin();

        // Act & Assert
        plugin.Initialize(); // Should not throw
    }

    [TestMethod]
    public void AzureCtsPlugin_Commands_AreCorrectTypes()
    {
        // Arrange & Act
        var plugin = new AzureCtsPlugin();

        // Assert
        var registerCommand = plugin.Commands.FirstOrDefault(c => c.Name == "cts_register");
        var verifyCommand = plugin.Commands.FirstOrDefault(c => c.Name == "cts_verify");

        Assert.IsNotNull(registerCommand);
        Assert.IsNotNull(verifyCommand);
        Assert.IsInstanceOfType(registerCommand, typeof(RegisterCommand));
        Assert.IsInstanceOfType(verifyCommand, typeof(VerifyCommand));
    }
}

/// <summary>
/// Tests for the RegisterCommand class.
/// </summary>
[TestClass]
public class RegisterCommandTests
{
    [TestMethod]
    public void RegisterCommand_Properties_ReturnCorrectValues()
    {
        // Arrange & Act
        var command = new RegisterCommand();

        // Assert
        Assert.AreEqual("cts_register", command.Name);
        Assert.AreEqual("Register a COSE Sign1 message with Azure Code Transparency Service", command.Description);
        Assert.IsTrue(command.Usage.Contains("cts_register"));
        Assert.IsTrue(command.Usage.Contains("--endpoint"));
        Assert.IsTrue(command.Usage.Contains("--payload"));
        Assert.IsTrue(command.Usage.Contains("--signature"));
        
        Assert.IsNotNull(command.Options);
        Assert.IsTrue(command.Options.ContainsKey("endpoint"));
        Assert.IsTrue(command.Options.ContainsKey("payload"));
        Assert.IsTrue(command.Options.ContainsKey("signature"));
        Assert.IsTrue(command.Options.ContainsKey("token-env"));
        Assert.IsTrue(command.Options.ContainsKey("output"));
        Assert.IsTrue(command.Options.ContainsKey("timeout"));
    }

    [TestMethod]
    public async Task RegisterCommand_ExecuteAsync_MissingEndpoint_ReturnsInvalidArguments()
    {
        // Arrange
        var command = new RegisterCommand();
        var configData = new Dictionary<string, string?>
        {
            { "payload", "test-payload.bin" },
            { "signature", "test-signature.cose" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        var result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task RegisterCommand_ExecuteAsync_MissingPayload_ReturnsInvalidArguments()
    {
        // Arrange
        var command = new RegisterCommand();
        var configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "signature", "test-signature.cose" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        var result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task RegisterCommand_ExecuteAsync_MissingSignature_ReturnsInvalidArguments()
    {
        // Arrange
        var command = new RegisterCommand();
        var configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "payload", "test-payload.bin" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        var result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task RegisterCommand_ExecuteAsync_NonExistentPayloadFile_ReturnsFailure()
    {
        // Arrange
        var command = new RegisterCommand();
        var configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "payload", "non-existent-payload.bin" },
            { "signature", "non-existent-signature.cose" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        var result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public async Task RegisterCommand_ExecuteAsync_InvalidTimeout_ReturnsInvalidArguments()
    {
        // Arrange
        var command = new RegisterCommand();
        var configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "payload", "test-payload.bin" },
            { "signature", "test-signature.cose" },
            { "timeout", "invalid-timeout" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        var result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    [TestMethod]
    public async Task RegisterCommand_ExecuteAsync_WithCancellation_ReturnsInvalidArgumentValue()
    {
        // Arrange
        var command = new RegisterCommand();
        
        // Create temporary files that exist but contain no meaningful data
        string tempPayloadFile = Path.GetTempFileName();
        string tempSignatureFile = Path.GetTempFileName();
        
        try
        {
            // Write minimal content so files exist
            await File.WriteAllTextAsync(tempPayloadFile, "test");
            await File.WriteAllBytesAsync(tempSignatureFile, new byte[] { 0x01, 0x02, 0x03 }); // Invalid COSE but will fail later
            
            var configData = new Dictionary<string, string?>
            {
                { "endpoint", "https://example.cts.azure.com" },
                { "payload", tempPayloadFile },
                { "signature", tempSignatureFile }
            };
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(configData)
                .Build();
            var cancellationToken = new CancellationToken(true);

            // Act
            var result = await command.ExecuteAsync(configuration, cancellationToken);

            // Assert
            Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
        }
        finally
        {
            // Clean up temporary files
            try { File.Delete(tempPayloadFile); } catch { }
            try { File.Delete(tempSignatureFile); } catch { }
        }
    }
}

/// <summary>
/// Tests for the VerifyCommand class.
/// </summary>
[TestClass]
public class VerifyCommandTests
{
    [TestMethod]
    public void VerifyCommand_Properties_ReturnCorrectValues()
    {
        // Arrange & Act
        var command = new VerifyCommand();

        // Assert
        Assert.AreEqual("cts_verify", command.Name);
        Assert.AreEqual("Verify a COSE Sign1 message with Azure Code Transparency Service", command.Description);
        Assert.IsTrue(command.Usage.Contains("cts_verify"));
        Assert.IsTrue(command.Usage.Contains("--endpoint"));
        Assert.IsTrue(command.Usage.Contains("--payload"));
        Assert.IsTrue(command.Usage.Contains("--signature"));
        
        Assert.IsNotNull(command.Options);
        Assert.IsTrue(command.Options.ContainsKey("endpoint"));
        Assert.IsTrue(command.Options.ContainsKey("payload"));
        Assert.IsTrue(command.Options.ContainsKey("signature"));
        Assert.IsTrue(command.Options.ContainsKey("token-env"));
        Assert.IsTrue(command.Options.ContainsKey("output"));
        Assert.IsTrue(command.Options.ContainsKey("receipt"));
        Assert.IsTrue(command.Options.ContainsKey("timeout"));
    }

    [TestMethod]
    public async Task VerifyCommand_ExecuteAsync_MissingEndpoint_ReturnsInvalidArguments()
    {
        // Arrange
        var command = new VerifyCommand();
        var configData = new Dictionary<string, string?>
        {
            { "payload", "test-payload.bin" },
            { "signature", "test-signature.cose" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        var result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task VerifyCommand_ExecuteAsync_MissingPayload_ReturnsInvalidArguments()
    {
        // Arrange
        var command = new VerifyCommand();
        var configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "signature", "test-signature.cose" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        var result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task VerifyCommand_ExecuteAsync_MissingSignature_ReturnsInvalidArguments()
    {
        // Arrange
        var command = new VerifyCommand();
        var configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "payload", "test-payload.bin" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        var result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task VerifyCommand_ExecuteAsync_NonExistentPayloadFile_ReturnsFailure()
    {
        // Arrange
        var command = new VerifyCommand();
        var configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "payload", "non-existent-payload.bin" },
            { "signature", "non-existent-signature.cose" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        var result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public async Task VerifyCommand_ExecuteAsync_InvalidTimeout_ReturnsInvalidArguments()
    {
        // Arrange
        var command = new VerifyCommand();
        var configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "payload", "test-payload.bin" },
            { "signature", "test-signature.cose" },
            { "timeout", "invalid-timeout" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        var result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    [TestMethod]
    public async Task VerifyCommand_ExecuteAsync_WithCancellation_ReturnsInvalidArgumentValue()
    {
        // Arrange
        var command = new VerifyCommand();
        
        // Create temporary files that exist but contain no meaningful data
        string tempPayloadFile = Path.GetTempFileName();
        string tempSignatureFile = Path.GetTempFileName();
        
        try
        {
            // Write minimal content so files exist
            await File.WriteAllTextAsync(tempPayloadFile, "test");
            await File.WriteAllBytesAsync(tempSignatureFile, new byte[] { 0x01, 0x02, 0x03 }); // Invalid COSE but will fail later
            
            var configData = new Dictionary<string, string?>
            {
                { "endpoint", "https://example.cts.azure.com" },
                { "payload", tempPayloadFile },
                { "signature", tempSignatureFile }
            };
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(configData)
                .Build();
            var cancellationToken = new CancellationToken(true);

            // Act
            var result = await command.ExecuteAsync(configuration, cancellationToken);

            // Assert
            Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
        }
        finally
        {
            // Clean up temporary files
            try { File.Delete(tempPayloadFile); } catch { }
            try { File.Delete(tempSignatureFile); } catch { }
        }
    }
}

/// <summary>
/// Tests for the CodeTransparencyClientHelper class.
/// </summary>
[TestClass]
public class CodeTransparencyClientHelperTests
{
    private const string TestEndpoint = "https://test.confidential-ledger.azure.com";
    private const string TestToken = "test-token-12345";
    private const string TestEnvVarName = "TEST_CTS_TOKEN";

    [TestMethod]
    public async Task CreateClientAsync_WithTokenFromDefaultEnvironmentVariable_CreatesClient()
    {
        // Arrange
        Environment.SetEnvironmentVariable("AZURE_CTS_TOKEN", TestToken);
        try
        {
            // Act
            var client = await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, null);

            // Assert
            Assert.IsNotNull(client);
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable("AZURE_CTS_TOKEN", null);
        }
    }

    [TestMethod]
    public async Task CreateClientAsync_WithTokenFromCustomEnvironmentVariable_CreatesClient()
    {
        // Arrange
        Environment.SetEnvironmentVariable(TestEnvVarName, TestToken);
        try
        {
            // Act
            var client = await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, TestEnvVarName);

            // Assert
            Assert.IsNotNull(client);
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable(TestEnvVarName, null);
        }
    }

    [TestMethod]
    public async Task CreateClientAsync_WithoutTokenEnvironmentVariable_UsesDefaultCredential()
    {
        // Arrange
        Environment.SetEnvironmentVariable("AZURE_CTS_TOKEN", null);
        Environment.SetEnvironmentVariable(TestEnvVarName, null);

        // Act & Assert
        // This test verifies that when no token is found, it attempts to use DefaultAzureCredential
        // In a test environment without Azure credentials, this will throw a CredentialUnavailableException
        // which is the expected behavior - the method should attempt to use DefaultAzureCredential
        await Assert.ThrowsExceptionAsync<Azure.Identity.CredentialUnavailableException>(
            async () => await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, TestEnvVarName));
    }

    [TestMethod]
    public async Task CreateClientAsync_WithEmptyTokenEnvironmentVariable_UsesDefaultCredential()
    {
        // Arrange
        Environment.SetEnvironmentVariable(TestEnvVarName, "");
        try
        {
            // Act & Assert
            // This test verifies that when token is empty, it attempts to use DefaultAzureCredential
            // In a test environment without Azure credentials, this will throw a CredentialUnavailableException
            // which is the expected behavior - the method should attempt to use DefaultAzureCredential
            await Assert.ThrowsExceptionAsync<Azure.Identity.CredentialUnavailableException>(
                async () => await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, TestEnvVarName));
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable(TestEnvVarName, null);
        }
    }
}
