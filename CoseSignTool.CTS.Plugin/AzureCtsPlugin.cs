// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.CTS.Plugin;

/// <summary>
/// Azure Code Transparency Service plugin for CoseSignTool.
/// </summary>
public class AzureCtsPlugin : ICoseSignToolPlugin
{
    private readonly List<IPluginCommand> _commands;

    /// <summary>
    /// Initializes a new instance of the <see cref="AzureCtsPlugin"/> class.
    /// </summary>
    public AzureCtsPlugin()
    {
        _commands = new List<IPluginCommand>
        {
            new RegisterCommand(),
            new VerifyCommand()
        };
    }

    /// <inheritdoc/>
    public string Name => "Azure Code Transparency Service";

    /// <inheritdoc/>
    public string Version => 
        System.Reflection.Assembly.GetExecutingAssembly()
            .GetName()
            .Version?
            .ToString() ?? "1.0.0";

    /// <inheritdoc/>
    public string Description => "Provides Azure Code Transparency Service integration for registering and verifying COSE Sign1 messages.";

    /// <inheritdoc/>
    public IEnumerable<IPluginCommand> Commands => _commands;

    /// <inheritdoc/>
    public void Initialize(IConfiguration? configuration = null)
    {
        // Perform any plugin-specific initialization here
        // For now, no initialization is required for the Azure CTS plugin
    }
}
