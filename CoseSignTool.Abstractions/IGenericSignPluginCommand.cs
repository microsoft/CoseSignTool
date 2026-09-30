// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Identifies a plugin command that requires the host's generic sign command to run first.
/// </summary>
public interface IGenericSignPluginCommand
{
    /// <summary>
    /// Gets the certificate provider used by the generic sign command.
    /// </summary>
    string CertificateProviderName { get; }

    /// <summary>
    /// Gets a value indicating whether the generated COSE statement embeds the payload.
    /// </summary>
    bool EmbedPayload { get; }
}
