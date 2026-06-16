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
/// <remarks>
/// Marked <see cref="DoNotParallelizeAttribute"/> because every test mutates the process-wide
/// environment variables <c>MST_TOKEN</c> and <c>TEST_CTS_TOKEN</c>. Even with per-test
/// try/finally blocks, concurrent execution within the class would race on the env-var slot.
/// <see cref="TestInitialize"/> / <see cref="TestCleanup"/> snapshot and restore the values
/// so a test that throws en route still leaves the process clean for downstream classes.
/// </remarks>
[TestClass]
[DoNotParallelize]
public class CodeTransparencyClientHelperTests
{
    private const string TestEndpoint = "https://test.confidential-ledger.azure.com";
    private const string TestToken = "test-token-12345";
    private const string TestEnvVarName = "TEST_CTS_TOKEN";

    private string? OriginalMstToken;
    private string? OriginalTestEnvVar;

    [TestInitialize]
    public void Setup()
    {
        OriginalMstToken = Environment.GetEnvironmentVariable("MST_TOKEN");
        OriginalTestEnvVar = Environment.GetEnvironmentVariable(TestEnvVarName);

        // Start every test from a known-clean env-var state.
        Environment.SetEnvironmentVariable("MST_TOKEN", null);
        Environment.SetEnvironmentVariable(TestEnvVarName, null);
    }

    [TestCleanup]
    public void Cleanup()
    {
        // Restore whatever the host shell had set so other test classes (or interactive
        // re-runs) are unaffected by our mutations, even if a test threw mid-flight.
        Environment.SetEnvironmentVariable("MST_TOKEN", OriginalMstToken);
        Environment.SetEnvironmentVariable(TestEnvVarName, OriginalTestEnvVar);
    }

    [TestMethod]
    public async Task CreateClientAsync_WithTokenFromDefaultEnvironmentVariable_CreatesClient()
    {
        // Arrange
        Environment.SetEnvironmentVariable("MST_TOKEN", TestToken);

        // Act
        Azure.Security.CodeTransparency.CodeTransparencyClient client = await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, null, useAzureAuth: false);

        // Assert
        Assert.IsNotNull(client);
    }

    [TestMethod]
    public async Task CreateClientAsync_WithTokenFromCustomEnvironmentVariable_CreatesClient()
    {
        // Arrange
        Environment.SetEnvironmentVariable(TestEnvVarName, TestToken);

        // Act
        Azure.Security.CodeTransparency.CodeTransparencyClient client = await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, TestEnvVarName, useAzureAuth: false);

        // Assert
        Assert.IsNotNull(client);
    }

    [TestMethod]
    public async Task CreateClientAsync_WithoutTokenAndDefaults_CreatesAnonymousClient()
    {
        // Arrange — env vars are clean per [TestInitialize].

        // Act - default behaviour (useAzureAuth=false) yields an anonymous client; no
        // network or credential acquisition occurs.
        Azure.Security.CodeTransparency.CodeTransparencyClient client = await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, null, useAzureAuth: false);

        // Assert
        Assert.IsNotNull(client);
    }

    [TestMethod]
    public async Task CreateClientAsync_WithoutTokenAndAzureAuth_UsesDefaultCredential()
    {
        // Arrange — env vars are clean per [TestInitialize].
        try
        {
            // Act
            Azure.Security.CodeTransparency.CodeTransparencyClient client = await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, null, useAzureAuth: true);

            // Assert
            // If DefaultAzureCredential succeeds (e.g., Azure CLI is logged in), the client should be created.
            Assert.IsNotNull(client);
        }
        catch (Azure.Identity.CredentialUnavailableException)
        {
            // In a test environment without Azure credentials, DefaultAzureCredential will throw
            // CredentialUnavailableException. That is also valid behaviour for this opt-in path.
            Assert.IsTrue(true, "DefaultAzureCredential correctly threw CredentialUnavailableException when no credentials are available");
        }
    }

    [TestMethod]
    public async Task CreateClientAsync_WithExplicitTokenEnvButMissingValue_ThrowsInvalidOperation()
    {
        // Arrange — explicit env var name supplied but the env var is unset (per [TestInitialize]).

        // Act / Assert
        InvalidOperationException ex = await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, TestEnvVarName, useAzureAuth: false));
        StringAssert.Contains(ex.Message, TestEnvVarName);
    }

    [TestMethod]
    public async Task CreateClientAsync_WithExplicitTokenEnvButWhitespaceValue_ThrowsInvalidOperation()
    {
        // Arrange — explicit env var name supplied but the env var is whitespace.
        Environment.SetEnvironmentVariable(TestEnvVarName, "   ");

        // Act / Assert
        InvalidOperationException ex = await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, TestEnvVarName, useAzureAuth: false));
        StringAssert.Contains(ex.Message, TestEnvVarName);
    }

    [TestMethod]
    public async Task CreateClientAsync_WithBothTokenAndAzureAuth_TokenWins()
    {
        // Arrange
        Environment.SetEnvironmentVariable("MST_TOKEN", TestToken);

        // Act — even with --azure-auth set, an explicit MST_TOKEN should be used
        // (no DefaultAzureCredential acquisition takes place).
        Azure.Security.CodeTransparency.CodeTransparencyClient client = await CodeTransparencyClientHelper.CreateClientAsync(TestEndpoint, null, useAzureAuth: true);

        // Assert
        Assert.IsNotNull(client);
    }
}

/// <summary>
/// Tests that verify the <c>--azure-auth</c> CLI flag is wired correctly through the option
/// metadata on both MST commands. These exercise the boolean-flag plumbing — a missing
/// <c>BooleanOptions</c> entry would cause the host CLI parser to reject a bare
/// <c>--azure-auth</c>, which would silently re-introduce the bug we just fixed.
/// </summary>
[TestClass]
public class MstAzureAuthFlagWiringTests
{
    [TestMethod]
    public void RegisterCommand_Options_ContainsAzureAuth()
    {
        // Arrange
        RegisterCommand command = new RegisterCommand();

        // Assert
        Assert.IsTrue(command.Options.ContainsKey("azure-auth"),
            "RegisterCommand.Options must include azure-auth so the CLI parser recognises --azure-auth.");
    }

    [TestMethod]
    public void RegisterCommand_BooleanOptions_ContainsAzureAuth()
    {
        // Arrange
        RegisterCommand command = new RegisterCommand();

        // Assert
        Assert.IsTrue(command.BooleanOptions.Contains("azure-auth"),
            "RegisterCommand.BooleanOptions must include azure-auth so a bare --azure-auth is accepted without a value.");
    }

    [TestMethod]
    public void VerifyCommand_Options_ContainsAzureAuth()
    {
        // Arrange
        VerifyCommand command = new VerifyCommand();

        // Assert
        Assert.IsTrue(command.Options.ContainsKey("azure-auth"),
            "VerifyCommand.Options must include azure-auth so the CLI parser recognises --azure-auth.");
    }

    [TestMethod]
    public void VerifyCommand_BooleanOptions_ContainsAzureAuth()
    {
        // Arrange
        VerifyCommand command = new VerifyCommand();

        // Assert
        Assert.IsTrue(command.BooleanOptions.Contains("azure-auth"),
            "VerifyCommand.BooleanOptions must include azure-auth so a bare --azure-auth is accepted without a value.");
    }

    [TestMethod]
    public void BooleanOptions_IsSharedAcrossInstances()
    {
        // Arrange
        RegisterCommand register1 = new RegisterCommand();
        RegisterCommand register2 = new RegisterCommand();
        VerifyCommand verify = new VerifyCommand();

        // Assert
        // Locks in the perf optimisation: BooleanOptions is backed by a single static array,
        // not allocated per instance. ReferenceEquals on the underlying collection guarantees this.
        Assert.AreSame(register1.BooleanOptions, register2.BooleanOptions,
            "RegisterCommand.BooleanOptions must be the same reference across instances (backed by static readonly).");
        Assert.AreSame(register1.BooleanOptions, verify.BooleanOptions,
            "BooleanOptions must be the same reference across all MST commands (shared static readonly).");
    }
}




