// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Optional interface for verification roots that want to include other roots' options
/// on their <c>verify &lt;root&gt;</c> command surface.
/// </summary>
/// <remarks>
/// This is a command-line scoping feature only. It does not automatically activate other roots.
/// Activation remains controlled by each provider's <see cref="IVerificationProvider.IsActivated" />.
/// </remarks>
public interface IVerificationRootOptionScopeProvider : IVerificationRootProvider
{
    /// <summary>
    /// Gets additional root IDs whose options should be included under this root command.
    /// The host implicitly includes the current root's own ID.
    /// </summary>
    IReadOnlyList<string> AdditionalRootIdsForOptionScope { get; }
}
