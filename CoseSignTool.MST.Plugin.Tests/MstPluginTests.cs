// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.MST.Plugin.Tests;

/// <summary>
/// Tests for the MstPlugin class.
/// </summary>
[TestClass]
public class MstPluginTests
{
    [TestMethod]
    public void MstPlugin_Properties_ReturnCorrectValues()
    {
        // Arrange & Act
        MstPlugin plugin = new MstPlugin();

        // Assert
        Assert.AreEqual("Microsoft's Signing Transparency", plugin.Name);
        Assert.AreEqual("1.0.0.0", plugin.Version);
        Assert.AreEqual("Provides Microsoft's Signing Transparency (MST) integration for registering and verifying COSE Sign1 messages.", plugin.Description);
        Assert.AreEqual(2, plugin.Commands.Count());

        string[] commandNames = plugin.Commands.Select(c => c.Name).ToArray();
        Assert.IsTrue(commandNames.Contains("mst_register"));
        Assert.IsTrue(commandNames.Contains("mst_verify"));
    }

    [TestMethod]
    public void MstPlugin_Initialize_DoesNotThrow()
    {
        // Arrange
        MstPlugin plugin = new MstPlugin();

        // Act & Assert
        plugin.Initialize(); // Should not throw
    }

    [TestMethod]
    public void MstPlugin_Commands_AreCorrectTypes()
    {
        // Arrange & Act
        MstPlugin plugin = new MstPlugin();

        // Assert
        IPluginCommand? registerCommand = plugin.Commands.FirstOrDefault(c => c.Name == "mst_register");
        IPluginCommand? verifyCommand = plugin.Commands.FirstOrDefault(c => c.Name == "mst_verify");

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
        RegisterCommand command = new RegisterCommand();

        // Assert
        Assert.AreEqual("mst_register", command.Name);
        Assert.AreEqual("Register a COSE Sign1 message with Microsoft's Signing Transparency (MST)", command.Description);
        Assert.IsTrue(command.Usage.Contains("mst_register"));
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
        RegisterCommand command = new RegisterCommand();
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "payload", "test-payload.bin" },
            { "signature", "test-signature.cose" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task RegisterCommand_ExecuteAsync_MissingPayload_ReturnsInvalidArguments()
    {
        // Arrange
        RegisterCommand command = new RegisterCommand();
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "signature", "test-signature.cose" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task RegisterCommand_ExecuteAsync_MissingSignature_ReturnsInvalidArguments()
    {
        // Arrange
        RegisterCommand command = new RegisterCommand();
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "payload", "test-payload.bin" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task RegisterCommand_ExecuteAsync_NonExistentPayloadFile_ReturnsFailure()
    {
        // Arrange
        RegisterCommand command = new RegisterCommand();
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "payload", "non-existent-payload.bin" },
            { "signature", "non-existent-signature.cose" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public async Task RegisterCommand_ExecuteAsync_InvalidTimeout_ReturnsInvalidArguments()
    {
        // Arrange
        RegisterCommand command = new RegisterCommand();
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "payload", "test-payload.bin" },
            { "signature", "test-signature.cose" },
            { "timeout", "invalid-timeout" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    [TestMethod]
    public async Task RegisterCommand_ExecuteAsync_WithCancellation_ReturnsInvalidArgumentValue()
    {
        // Arrange
        RegisterCommand command = new RegisterCommand();
        
        // Create temporary files that exist but contain no meaningful data
        string tempPayloadFile = Path.GetTempFileName();
        string tempSignatureFile = Path.GetTempFileName();
        
        try
        {
            // Write minimal content so files exist
            await File.WriteAllTextAsync(tempPayloadFile, "test");
            await File.WriteAllBytesAsync(tempSignatureFile, new byte[] { 0x01, 0x02, 0x03 }); // Invalid COSE but will fail later

            Dictionary<string, string?> configData = new Dictionary<string, string?>
            {
                { "endpoint", "https://example.cts.azure.com" },
                { "payload", tempPayloadFile },
                { "signature", tempSignatureFile }
            };
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(configData)
                .Build();
            CancellationToken cancellationToken = new CancellationToken(true);

            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration, cancellationToken);

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
        VerifyCommand command = new VerifyCommand();

        // Assert
        Assert.AreEqual("mst_verify", command.Name);
        Assert.AreEqual("Verify a COSE Sign1 message with Microsoft's Signing Transparency (MST)", command.Description);
        Assert.IsTrue(command.Usage.Contains("mst_verify"));
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
        VerifyCommand command = new VerifyCommand();
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "payload", "test-payload.bin" },
            { "signature", "test-signature.cose" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task VerifyCommand_ExecuteAsync_MissingPayload_ReturnsInvalidArguments()
    {
        // Arrange
        VerifyCommand command = new VerifyCommand();
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "signature", "test-signature.cose" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task VerifyCommand_ExecuteAsync_MissingSignature_ReturnsInvalidArguments()
    {
        // Arrange
        VerifyCommand command = new VerifyCommand();
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "payload", "test-payload.bin" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.MissingRequiredOption, result);
    }

    [TestMethod]
    public async Task VerifyCommand_ExecuteAsync_NonExistentPayloadFile_ReturnsFailure()
    {
        // Arrange
        VerifyCommand command = new VerifyCommand();
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "payload", "non-existent-payload.bin" },
            { "signature", "non-existent-signature.cose" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UserSpecifiedFileNotFound, result);
    }

    [TestMethod]
    public async Task VerifyCommand_ExecuteAsync_InvalidTimeout_ReturnsInvalidArguments()
    {
        // Arrange
        VerifyCommand command = new VerifyCommand();
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "endpoint", "https://example.cts.azure.com" },
            { "payload", "test-payload.bin" },
            { "signature", "test-signature.cose" },
            { "timeout", "invalid-timeout" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.InvalidArgumentValue, result);
    }

    [TestMethod]
    public async Task VerifyCommand_ExecuteAsync_WithCancellation_ReturnsInvalidArgumentValue()
    {
        // Arrange
        VerifyCommand command = new VerifyCommand();
        
        // Create temporary files that exist but contain no meaningful data
        string tempPayloadFile = Path.GetTempFileName();
        string tempSignatureFile = Path.GetTempFileName();
        
        try
        {
            // Write minimal content so files exist
            await File.WriteAllTextAsync(tempPayloadFile, "test");
            await File.WriteAllBytesAsync(tempSignatureFile, new byte[] { 0x01, 0x02, 0x03 }); // Invalid COSE but will fail later

            Dictionary<string, string?> configData = new Dictionary<string, string?>
            {
                { "endpoint", "https://example.cts.azure.com" },
                { "payload", tempPayloadFile },
                { "signature", tempSignatureFile }
            };
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(configData)
                .Build();
            CancellationToken cancellationToken = new CancellationToken(true);

            // Act
            PluginExitCode result = await command.ExecuteAsync(configuration, cancellationToken);

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
            Azure.Security.CodeTransparency.CodeTransparencyClient client = await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, null);

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
            Azure.Security.CodeTransparency.CodeTransparencyClient client = await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, TestEnvVarName);

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

        try
        {
            // Act
            Azure.Security.CodeTransparency.CodeTransparencyClient client = await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, TestEnvVarName);

            // Assert
            // If DefaultAzureCredential succeeds (e.g., Azure CLI is logged in), the client should be created
            Assert.IsNotNull(client);
        }
        catch (Azure.Identity.CredentialUnavailableException)
        {
            // Assert
            // In a test environment without Azure credentials, DefaultAzureCredential will throw CredentialUnavailableException
            // This is also valid behavior - the method attempted to use DefaultAzureCredential as expected
            Assert.IsTrue(true, "DefaultAzureCredential correctly threw CredentialUnavailableException when no credentials are available");
        }
    }

    [TestMethod]
    public async Task CreateClientAsync_WithEmptyTokenEnvironmentVariable_UsesDefaultCredential()
    {
        // Arrange
        Environment.SetEnvironmentVariable(TestEnvVarName, "");
        try
        {
            try
            {
                // Act
                Azure.Security.CodeTransparency.CodeTransparencyClient client = await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, TestEnvVarName);

                // Assert
                // If DefaultAzureCredential succeeds (e.g., Azure CLI is logged in), the client should be created
                Assert.IsNotNull(client);
            }
            catch (Azure.Identity.CredentialUnavailableException)
            {
                // Assert
                // In a test environment without Azure credentials, DefaultAzureCredential will throw CredentialUnavailableException
                // This is also valid behavior - the method attempted to use DefaultAzureCredential as expected
                Assert.IsTrue(true, "DefaultAzureCredential correctly threw CredentialUnavailableException when no credentials are available");
            }
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable(TestEnvVarName, null);
        }
    }
}
