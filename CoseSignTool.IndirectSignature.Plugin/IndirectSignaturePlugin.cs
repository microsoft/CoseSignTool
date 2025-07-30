// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.IndirectSignature.Plugin;

/// <summary>
/// Plugin for indirect COSE signature operations.
/// </summary>
public class IndirectSignaturePlugin : ICoseSignToolPlugin
{
    private readonly List<IPluginCommand> _commands;

    /// <summary>
    /// Initializes a new instance of the <see cref="IndirectSignaturePlugin"/> class.
    /// </summary>
    public IndirectSignaturePlugin()
    {
        _commands = new List<IPluginCommand>
        {
            new IndirectSignCommand(),
            new IndirectVerifyCommand()
        };
    }

    /// <inheritdoc/>
    public string Name => "Indirect Signature";

    /// <inheritdoc/>
    public string Version => 
        System.Reflection.Assembly.GetExecutingAssembly()
            .GetName()
            .Version?
            .ToString() ?? "1.0.0";

    /// <inheritdoc/>
    public string Description => "Provides indirect COSE Sign1 signature creation and verification capabilities for SCITT compliance.";

    /// <inheritdoc/>
    public IEnumerable<IPluginCommand> Commands => _commands;

    /// <inheritdoc/>
    public void Initialize(IConfiguration? configuration = null)
    {
        // Perform any plugin-specific initialization here
        // For now, no initialization is required for the Indirect Signature plugin
    }
}
