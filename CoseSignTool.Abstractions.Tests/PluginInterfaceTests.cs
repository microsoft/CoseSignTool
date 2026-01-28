// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Tests;

/// <summary>
/// Test implementation of IPluginCommand for testing purposes.
/// </summary>
public class TestPluginCommand : PluginCommandBase
{
    /// <inheritdoc/>
    public override string Name => "test";
    
    /// <inheritdoc/>
    public override string Description => "Test command for unit testing";
    
    /// <inheritdoc/>
    public override string Usage => "test [options]";
    
    /// <inheritdoc/>
    public override IDictionary<string, string> Options => new Dictionary<string, string>();
    
    private readonly PluginExitCode ExitCode;
    private readonly bool ShouldThrow;

    /// <summary>
    /// Initializes a new instance of the TestPluginCommand class.
    /// </summary>
    /// <param name="exitCode">The exit code to return.</param>
    /// <param name="shouldThrow">Whether to throw an exception.</param>
    public TestPluginCommand(PluginExitCode exitCode = PluginExitCode.Success, bool shouldThrow = false)
    {
        this.ExitCode = exitCode;
        this.ShouldThrow = shouldThrow;
    }

    /// <inheritdoc/>
    public override Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }

        if (ShouldThrow)
        {
            throw new InvalidOperationException("Test exception");
        }

        return Task.FromResult(ExitCode);
    }
}

/// <summary>
/// Test implementation of ICoseSignToolPlugin for testing purposes.
/// </summary>
public class TestPlugin : ICoseSignToolPlugin
{
    /// <inheritdoc/>
    public string Name => "TestPlugin";
    
    /// <inheritdoc/>
    public string Version => "1.0.0";
    
    /// <inheritdoc/>
    public string Description => "Test plugin for unit testing";

    private readonly List<IPluginCommand> CommandsList;
    private bool IsInitializedField;

    /// <summary>
    /// Initializes a new instance of the TestPlugin class.
    /// </summary>
    /// <param name="commands">The commands to include in the plugin.</param>
    public TestPlugin(params IPluginCommand[] commands)
    {
        this.CommandsList = new List<IPluginCommand>(commands);
    }

    /// <inheritdoc/>
    public IEnumerable<IPluginCommand> Commands => CommandsList;

    /// <summary>
    /// Gets a value indicating whether the plugin has been initialized.
    /// </summary>
    public bool IsInitialized => IsInitializedField;

    /// <inheritdoc/>
    public void Initialize(IConfiguration? configuration = null)
    {
        IsInitializedField = true;
    }
}

/// <summary>
/// Tests for the plugin command base class and interfaces.
/// </summary>
[TestClass]
public class PluginCommandBaseTests
{
    /// <summary>
    /// Tests TestPluginCommand properties return correct values.
    /// </summary>
    [TestMethod]
    public void TestPluginCommand_Properties_ReturnCorrectValues()
    {
        // Arrange & Act
        TestPluginCommand command = new TestPluginCommand();

        // Assert
        Assert.AreEqual("test", command.Name);
        Assert.AreEqual("Test command for unit testing", command.Description);
        Assert.AreEqual("test [options]", command.Usage);
        Assert.IsNotNull(command.Options);
        Assert.AreEqual(0, command.Options.Count);
    }

    /// <summary>
    /// Tests TestPluginCommand ExecuteAsync returns success.
    /// </summary>
    [TestMethod]
    public async Task TestPluginCommand_ExecuteAsync_ReturnsSuccess()
    {
        // Arrange
        TestPluginCommand command = new TestPluginCommand(PluginExitCode.Success);
        Dictionary<string, string?> configData = new Dictionary<string, string?>();
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.Success, result);
    }

    /// <summary>
    /// Tests TestPluginCommand ExecuteAsync returns UnknownError.
    /// </summary>
    [TestMethod]
    public async Task TestPluginCommand_ExecuteAsync_ReturnsFailure()
    {
        // Arrange
        TestPluginCommand command = new TestPluginCommand(PluginExitCode.UnknownError);
        Dictionary<string, string?> configData = new Dictionary<string, string?>();
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        PluginExitCode result = await command.ExecuteAsync(configuration);

        // Assert
        Assert.AreEqual(PluginExitCode.UnknownError, result);
    }

    /// <summary>
    /// Tests TestPluginCommand ExecuteAsync with cancellation throws OperationCanceledException.
    /// </summary>
    [TestMethod]
    public async Task TestPluginCommand_ExecuteAsync_WithCancellation_ThrowsOperationCanceledException()
    {
        // Arrange
        TestPluginCommand command = new TestPluginCommand();
        Dictionary<string, string?> configData = new Dictionary<string, string?>();
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();
        CancellationToken cancellationToken = new CancellationToken(true);

        // Act & Assert
        await Assert.ThrowsExceptionAsync<OperationCanceledException>(
            () => command.ExecuteAsync(configuration, cancellationToken));
    }

    /// <summary>
    /// Tests TestPluginCommand ExecuteAsync throws exception propagates exception.
    /// </summary>
    [TestMethod]
    public async Task TestPluginCommand_ExecuteAsync_ThrowsException_PropagatesException()
    {
        // Arrange
        TestPluginCommand command = new TestPluginCommand(shouldThrow: true);
        Dictionary<string, string?> configData = new Dictionary<string, string?>();
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act & Assert
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => command.ExecuteAsync(configuration));
    }

    /// <summary>
    /// Tests that TestPluginCommand BooleanOptions returns empty collection by default.
    /// </summary>
    [TestMethod]
    public void TestPluginCommand_BooleanOptions_ReturnsEmptyByDefault()
    {
        // Arrange & Act
        TestPluginCommand command = new TestPluginCommand();

        // Assert
        Assert.IsNotNull(command.BooleanOptions);
        Assert.AreEqual(0, command.BooleanOptions.Count);
    }

    /// <summary>
    /// Tests GetBooleanFlag returns false when key is not present.
    /// </summary>
    [TestMethod]
    public void GetBooleanFlag_KeyNotPresent_ReturnsFalse()
    {
        // Arrange
        Dictionary<string, string?> configData = new Dictionary<string, string?>();
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        bool result = TestablePluginCommand.TestGetBooleanFlag(configuration, "nonexistent");

        // Assert
        Assert.IsFalse(result);
    }

    /// <summary>
    /// Tests GetBooleanFlag returns true when key is present with empty value.
    /// </summary>
    [TestMethod]
    public void GetBooleanFlag_KeyPresentWithEmptyValue_ReturnsTrue()
    {
        // Arrange
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "my-flag", "" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        bool result = TestablePluginCommand.TestGetBooleanFlag(configuration, "my-flag");

        // Assert
        Assert.IsTrue(result);
    }

    /// <summary>
    /// Tests GetBooleanFlag returns true when key has value "true".
    /// </summary>
    [TestMethod]
    public void GetBooleanFlag_KeyPresentWithTrueValue_ReturnsTrue()
    {
        // Arrange
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "my-flag", "true" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        bool result = TestablePluginCommand.TestGetBooleanFlag(configuration, "my-flag");

        // Assert
        Assert.IsTrue(result);
    }

    /// <summary>
    /// Tests GetBooleanFlag returns true when key has any non-false value.
    /// </summary>
    [TestMethod]
    public void GetBooleanFlag_KeyPresentWithAnyNonFalseValue_ReturnsTrue()
    {
        // Arrange
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "my-flag", "anything" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        bool result = TestablePluginCommand.TestGetBooleanFlag(configuration, "my-flag");

        // Assert
        Assert.IsTrue(result);
    }

    /// <summary>
    /// Tests GetBooleanFlag returns false when key has value "false".
    /// </summary>
    [TestMethod]
    public void GetBooleanFlag_KeyPresentWithFalseValue_ReturnsFalse()
    {
        // Arrange
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "my-flag", "false" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        bool result = TestablePluginCommand.TestGetBooleanFlag(configuration, "my-flag");

        // Assert
        Assert.IsFalse(result);
    }

    /// <summary>
    /// Tests GetBooleanFlag returns false when key has value "FALSE" (case insensitive).
    /// </summary>
    [TestMethod]
    public void GetBooleanFlag_KeyPresentWithFalseValueUpperCase_ReturnsFalse()
    {
        // Arrange
        Dictionary<string, string?> configData = new Dictionary<string, string?>
        {
            { "my-flag", "FALSE" }
        };
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        bool result = TestablePluginCommand.TestGetBooleanFlag(configuration, "my-flag");

        // Assert
        Assert.IsFalse(result);
    }
}

/// <summary>
/// Testable version of PluginCommandBase that exposes protected methods for testing.
/// </summary>
public class TestablePluginCommand : PluginCommandBase
{
    /// <inheritdoc/>
    public override string Name => "testable";

    /// <inheritdoc/>
    public override string Description => "Testable command";

    /// <inheritdoc/>
    public override string Usage => "testable [options]";

    /// <inheritdoc/>
    public override IDictionary<string, string> Options => new Dictionary<string, string>();

    /// <inheritdoc/>
    public override Task<PluginExitCode> ExecuteAsync(IConfiguration configuration, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(PluginExitCode.Success);
    }

    /// <summary>
    /// Exposes the protected GetBooleanFlag method for testing.
    /// </summary>
    /// <param name="configuration">The configuration to check.</param>
    /// <param name="key">The key to look for.</param>
    /// <returns>True if the flag is set, false otherwise.</returns>
    public static bool TestGetBooleanFlag(IConfiguration configuration, string key)
    {
        return GetBooleanFlag(configuration, key);
    }
}

/// <summary>
/// Tests for the plugin interface implementations.
/// </summary>
[TestClass]
public class PluginInterfaceTests
{
    /// <summary>
    /// Tests that TestPlugin properties return correct values.
    /// </summary>
    [TestMethod]
    public void TestPlugin_Properties_ReturnCorrectValues()
    {
        // Arrange
        TestPluginCommand command1 = new TestPluginCommand();
        TestPluginCommand command2 = new TestPluginCommand();
        TestPlugin plugin = new TestPlugin(command1, command2);

        // Act & Assert
        Assert.AreEqual("TestPlugin", plugin.Name);
        Assert.AreEqual("1.0.0", plugin.Version);
        Assert.AreEqual("Test plugin for unit testing", plugin.Description);
        Assert.IsFalse(plugin.IsInitialized);
        Assert.AreEqual(2, plugin.Commands.Count());
        Assert.AreSame(command1, plugin.Commands.First());
        Assert.AreSame(command2, plugin.Commands.Skip(1).First());
    }

    /// <summary>
    /// Tests that TestPlugin Initialize method sets the initialized flag.
    /// </summary>
    [TestMethod]
    public void TestPlugin_Initialize_SetsInitializedFlag()
    {
        // Arrange
        TestPlugin plugin = new TestPlugin();

        // Act
        plugin.Initialize();

        // Assert
        Assert.IsTrue(plugin.IsInitialized);
    }

    /// <summary>
    /// Tests that TestPlugin with no commands has empty commands list.
    /// </summary>
    [TestMethod]
    public void TestPlugin_WithNoCommands_HasEmptyCommandsList()
    {
        // Arrange & Act
        TestPlugin plugin = new TestPlugin();

        // Assert
        Assert.AreEqual(0, plugin.Commands.Count());
    }
}

/// <summary>
/// Tests for the PluginExitCode enum.
/// </summary>
[TestClass]
public class PluginExitCodeTests
{
    /// <summary>
    /// Tests that PluginExitCode enum values have correct integer values.
    /// </summary>
    [TestMethod]
    public void PluginExitCode_Values_HaveCorrectIntegerValues()
    {
        // Assert
        Assert.AreEqual(0, (int)PluginExitCode.Success);
        Assert.AreEqual(1, (int)PluginExitCode.HelpRequested);
        Assert.AreEqual(2, (int)PluginExitCode.MissingRequiredOption);
    }

    /// <summary>
    /// Tests that PluginExitCode can be cast to integer.
    /// </summary>
    [TestMethod]
    public void PluginExitCode_CanBeCastToInt()
    {
        // Arrange
        PluginExitCode successCode = PluginExitCode.Success;
        PluginExitCode helpCode = PluginExitCode.HelpRequested;
        PluginExitCode missingOptionCode = PluginExitCode.MissingRequiredOption;

        // Act & Assert
        Assert.AreEqual(0, (int)successCode);
        Assert.AreEqual(1, (int)helpCode);
        Assert.AreEqual(2, (int)missingOptionCode);
    }
}
