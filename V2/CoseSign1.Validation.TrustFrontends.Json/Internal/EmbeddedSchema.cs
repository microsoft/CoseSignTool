// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json.Internal;

using System;
using System.IO;
using System.Reflection;
using System.Threading;
using global::Json.Schema;

/// <summary>
/// Loads the embedded <c>cose-tp/v1.json</c> schema lazily (and at most once per process)
/// from the manifest resource shipped in this assembly. Translation never touches the network.
/// </summary>
internal static class EmbeddedSchema
{
    private static JsonSchema? Loaded;
    private static byte[]? LoadedBytes;
    private static readonly Lock LoadLock = new();

    /// <summary>Gets the <see cref="JsonSchema"/> instance corresponding to the embedded resource.</summary>
    /// <returns>The compiled, deduplicated schema instance.</returns>
    public static JsonSchema Get()
    {
        if (Loaded is { } cached)
        {
            return cached;
        }

        lock (LoadLock)
        {
            if (Loaded is { } cached2)
            {
                return cached2;
            }

            byte[] bytes = ReadResourceBytes();
            JsonSchema schema = JsonSchema.FromText(System.Text.Encoding.UTF8.GetString(bytes));
            LoadedBytes = bytes;
            Loaded = schema;
            return schema;
        }
    }

    /// <summary>Gets the raw UTF-8 bytes of the embedded schema resource. Used by the on-disk drift assertion test.</summary>
    /// <returns>The embedded schema's bytes (UTF-8).</returns>
    public static byte[] GetBytes()
    {
        if (LoadedBytes is { } cached)
        {
            return cached;
        }

        _ = Get();
        return LoadedBytes ?? UnreachableLoadedBytesNull();
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = AssemblyStrings.JustifyDefensive)]
    private static byte[] UnreachableLoadedBytesNull() => throw new InvalidOperationException(AssemblyStrings.SchemaResourceName);

    private static byte[] ReadResourceBytes()
    {
        Assembly asm = typeof(EmbeddedSchema).Assembly;
        using Stream? stream = asm.GetManifestResourceStream(AssemblyStrings.SchemaResourceName);
        if (stream is null)
        {
            return UnreachableMissingResource();
        }

        using var ms = new MemoryStream(checked((int)stream.Length));
        stream.CopyTo(ms);
        return ms.ToArray();
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = AssemblyStrings.JustifyDefensive)]
    private static byte[] UnreachableMissingResource() => throw new InvalidOperationException(AssemblyStrings.SchemaResourceName);
}
