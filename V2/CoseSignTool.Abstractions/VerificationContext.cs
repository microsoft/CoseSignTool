// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Context information for verification that isn't available from command-line parsing alone.
/// </summary>
public sealed class VerificationContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="VerificationContext"/> class.
    /// </summary>
    /// <param name="detachedPayload">
    /// Detached payload bytes. For embedded signatures this is typically null.
    /// For detached signatures this is required to verify the signature.
    /// </param>
    public VerificationContext(ReadOnlyMemory<byte>? detachedPayload)
    {
        DetachedPayload = detachedPayload;
    }

    /// <summary>
    /// Gets the detached payload bytes, if present.
    /// </summary>
    public ReadOnlyMemory<byte>? DetachedPayload { get; }
}
