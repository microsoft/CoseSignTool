// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.AzureArtifactSigning.Plugin;

/// <summary>
/// Provides Azure Artifact Signing-specific commands.
/// </summary>
public sealed class AzureArtifactSigningCommandPlugin : ICoseSignToolPlugin
{
    private static readonly IPluginCommand[] PluginCommands =
    {
        new AzureArtifactSigningSignMstRegisterCommand()
    };

    /// <inheritdoc/>
    public string Name => "Azure Artifact Signing";

    /// <inheritdoc/>
    public string Version =>
        System.Reflection.Assembly.GetExecutingAssembly()
            .GetName()
            .Version?
            .ToString() ?? "1.0.0";

    /// <inheritdoc/>
    public string Description => "Provides Azure Artifact Signing-specific commands.";

    /// <inheritdoc/>
    public IEnumerable<IPluginCommand> Commands => PluginCommands;

    /// <inheritdoc/>
    public void Initialize(IConfiguration? configuration = null)
    {
    }
}
