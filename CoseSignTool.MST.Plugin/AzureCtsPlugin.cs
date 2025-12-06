// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.MST.Plugin;

/// <summary>
/// Microsoft's Signing Transparency (MST) plugin for CoseSignTool.
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
    public string Name => "Microsoft's Signing Transparency";

    /// <inheritdoc/>
    public string Version => 
        System.Reflection.Assembly.GetExecutingAssembly()
            .GetName()
            .Version?
            .ToString() ?? "1.0.0";

    /// <inheritdoc/>
    public string Description => "Provides Microsoft's Signing Transparency (MST) integration for registering and verifying COSE Sign1 messages.";

    /// <inheritdoc/>
    public IEnumerable<IPluginCommand> Commands => _commands;

    /// <inheritdoc/>
    public void Initialize(IConfiguration? configuration = null)
    {
        // Perform any plugin-specific initialization here
        // For now, no initialization is required for the MST plugin
    }
}
