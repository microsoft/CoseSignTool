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
        var command = new TestPluginCommand();

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
        var command = new TestPluginCommand(PluginExitCode.Success);
        var configData = new Dictionary<string, string?>();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        var result = await command.ExecuteAsync(configuration);

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
        var command = new TestPluginCommand(PluginExitCode.UnknownError);
        var configData = new Dictionary<string, string?>();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act
        var result = await command.ExecuteAsync(configuration);

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
        var command = new TestPluginCommand();
        var configData = new Dictionary<string, string?>();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();
        var cancellationToken = new CancellationToken(true);

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
        var command = new TestPluginCommand(shouldThrow: true);
        var configData = new Dictionary<string, string?>();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act & Assert
        await Assert.ThrowsExceptionAsync<InvalidOperationException>(
            () => command.ExecuteAsync(configuration));
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
        var command1 = new TestPluginCommand();
        var command2 = new TestPluginCommand();
        var plugin = new TestPlugin(command1, command2);

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
        var plugin = new TestPlugin();

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
        var plugin = new TestPlugin();

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
        var successCode = PluginExitCode.Success;
        var helpCode = PluginExitCode.HelpRequested;
        var missingOptionCode = PluginExitCode.MissingRequiredOption;

        // Act & Assert
        Assert.AreEqual(0, (int)successCode);
        Assert.AreEqual(1, (int)helpCode);
        Assert.AreEqual(2, (int)missingOptionCode);
    }
}
