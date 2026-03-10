// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Optional interface for signing material providers that want to expose additional CLI aliases.
/// </summary>
public interface ISigningMaterialProviderWithAliases : ISigningMaterialProvider
{
    /// <summary>
    /// Gets additional CLI aliases for the provider command token.
    /// </summary>
    IReadOnlyList<string> Aliases { get; }
}
