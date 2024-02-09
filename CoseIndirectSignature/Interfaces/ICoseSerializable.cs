// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseIndirectSignature.Interfaces;

using System.Formats.Cbor;

public interface ICoseSerializable
{
    /// <summary>
    /// Writes the object to the <see cref="CborWriter"/>.
    /// </summary>
    /// <param name="writer">The writer</param>
    void WriteToCbor(CborWriter writer);
    Task WriteToCborAsync(CborWriter writer);
}
