// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates;

using Microsoft.IO;

/// <summary>
/// Provides pooled MemoryStream instances to avoid Large Object Heap allocations.
/// </summary>
internal static class MemoryStreamPool
{
    private static readonly RecyclableMemoryStreamManager Manager = new();

    public static MemoryStream GetStream() => Manager.GetStream();
    public static MemoryStream GetStream(string tag) => Manager.GetStream(tag);
}