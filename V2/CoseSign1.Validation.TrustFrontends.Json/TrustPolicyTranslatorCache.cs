// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using CoseSign1.Validation.Trust.Frontends;

/// <summary>
/// In-process LRU cache fronting <see cref="CoseTpJsonFrontend"/>. The cache key is the SHA-256
/// of the canonical document bytes concatenated with the SHA-256 of the canonical parameter JSON
/// (D9). Capacity defaults to 32; configurable via <see cref="TrustPolicyTranslatorOptions"/>.
/// </summary>
/// <remarks>
/// <para>
/// Per §6.5.9 anti-pattern #4, the cache stores derived <see cref="TrustPolicyTranslationResult"/>
/// values for performance only — never as the policy of record. Cached entries are
/// reference-shared; callers must treat them as immutable (every cached field is a record /
/// readonly type, so this is enforced by construction).
/// </para>
/// <para>
/// Eviction policy is true LRU: every cache hit moves the entry to the most-recently-used
/// position and the eviction step removes the least-recently-used. The implementation uses a
/// simple linked-list-backed dictionary protected by a single lock; a 32-entry default keeps
/// contention well below noise even under high concurrency.
/// </para>
/// </remarks>
public sealed class TrustPolicyTranslatorCache
{
    private readonly TrustPolicyTranslatorOptions Options;
    private readonly LinkedList<CacheEntry> Lru = new();
    private readonly Dictionary<string, LinkedListNode<CacheEntry>> Map = new(StringComparer.Ordinal);
    private readonly Lock Sync = new();

    /// <summary>Initializes a new instance of the <see cref="TrustPolicyTranslatorCache"/> class.</summary>
    /// <param name="options">Cache configuration. <see langword="null"/> uses defaults.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <see cref="TrustPolicyTranslatorOptions.CacheCapacity"/> is non-positive.</exception>
    public TrustPolicyTranslatorCache(TrustPolicyTranslatorOptions? options = null)
    {
        Options = options ?? new TrustPolicyTranslatorOptions();
        if (Options.CacheCapacity <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options),
                Options.CacheCapacity,
                string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrCacheCapacityFormat, Options.CacheCapacity));
        }
    }

    /// <summary>Gets the active cache capacity.</summary>
    public int Capacity => Options.CacheCapacity;

    /// <summary>Gets the current number of entries in the cache.</summary>
    public int Count
    {
        get
        {
            lock (Sync)
            {
                return Map.Count;
            }
        }
    }

    /// <summary>
    /// Translates <paramref name="documentText"/> through <paramref name="frontend"/>, caching
    /// the result by canonical content hash + parameter hash so equal inputs return identical
    /// results without re-running schema validation.
    /// </summary>
    /// <param name="frontend">The translator implementation to invoke on cache miss.</param>
    /// <param name="documentText">The raw document text.</param>
    /// <param name="ctx">The translation context. Parameter values from <see cref="TrustPolicyTranslationContext.Parameters"/> are folded into the cache key.</param>
    /// <param name="documentSource">Optional source identifier (folded into key + diagnostics).</param>
    /// <returns>The translation result.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any required argument is null.</exception>
    public TrustPolicyTranslationResult TranslateText(
        CoseTpJsonFrontend frontend,
        string documentText,
        TrustPolicyTranslationContext ctx,
        string? documentSource = null)
    {
        if (frontend is null)
        {
            throw new ArgumentNullException(nameof(frontend), AssemblyStrings.ErrArgumentTranslatorNull);
        }

        if (documentText is null)
        {
            throw new ArgumentNullException(nameof(documentText), AssemblyStrings.ErrArgumentDocumentTextNull);
        }

        Cose.Abstractions.Guard.ThrowIfNull(ctx);

        string key = ComputeKey(documentText, ctx, documentSource);

        lock (Sync)
        {
            if (Map.TryGetValue(key, out LinkedListNode<CacheEntry>? hit))
            {
                Lru.Remove(hit);
                Lru.AddFirst(hit);
                return hit.Value.Result;
            }
        }

        TrustPolicyTranslationResult fresh = frontend.TranslateText(documentText, ctx, documentSource);

        lock (Sync)
        {
            if (!Map.ContainsKey(key))
            {
                LinkedListNode<CacheEntry> node = Lru.AddFirst(new CacheEntry(key, fresh));
                Map[key] = node;

                while (Map.Count > Options.CacheCapacity)
                {
                    LinkedListNode<CacheEntry>? lruNode = Lru.Last;
                    if (lruNode is null)
                    {
                        break;
                    }

                    Lru.RemoveLast();
                    Map.Remove(lruNode.Value.Key);
                }
            }
        }

        return fresh;
    }

    private static string ComputeKey(string documentText, TrustPolicyTranslationContext ctx, string? documentSource)
    {
        byte[] docBytes = Encoding.UTF8.GetBytes(documentText);
        byte[] docHash = SHA256.HashData(docBytes);

        // Canonical parameter projection: sort by name, project each name + value to a JSON
        // tuple, then re-canonicalise. Produces a deterministic byte stream regardless of the
        // dictionary's insertion order.
        var sorted = new SortedDictionary<string, JsonNode?>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, JsonNode> kvp in ctx.Parameters)
        {
            sorted[kvp.Key] = kvp.Value.DeepClone();
        }

        string paramJson = sorted.Count == 0 ? AssemblyStrings.EmptyParamObject : new JsonObject(sorted!).ToJsonString();
        byte[] paramHash = SHA256.HashData(Encoding.UTF8.GetBytes(paramJson));

        // Capability fingerprint — different available-fact sets yield different specs, so
        // include it in the key. Predicate schemas re-fingerprint via their JSON projection.
        string capsFingerprint = AssemblyStrings.KeySegmentSeparator;
        if (ctx.AvailableFacts is { } caps)
        {
            var capsBuilder = new StringBuilder();
            capsBuilder.Append(ctx.AllowUnknownFacts ? AssemblyStrings.CapsAllowUnknownPrefix : AssemblyStrings.CapsKnownPrefix);
            foreach (string id in caps.AvailableFactIds.OrderBy(s => s, StringComparer.Ordinal))
            {
                capsBuilder.Append(id);
                capsBuilder.Append(AssemblyStrings.CapsEntrySeparator);
            }

            if (caps.PredicateSchemas is { } schemas)
            {
                foreach (KeyValuePair<string, JsonNode> kvp in schemas.OrderBy(p => p.Key, StringComparer.Ordinal))
                {
                    capsBuilder.Append(kvp.Key);
                    capsBuilder.Append(AssemblyStrings.CapsKeyValueSeparator);
                    capsBuilder.Append(kvp.Value?.ToJsonString());
                    capsBuilder.Append(AssemblyStrings.CapsEntrySeparator);
                }
            }

            capsFingerprint = capsBuilder.ToString();
        }

        byte[] capsHash = SHA256.HashData(Encoding.UTF8.GetBytes(capsFingerprint));

        return string.Concat(
            Convert.ToHexString(docHash),
            AssemblyStrings.KeySegmentSeparator,
            Convert.ToHexString(paramHash),
            AssemblyStrings.KeySegmentSeparator,
            Convert.ToHexString(capsHash),
            AssemblyStrings.KeySegmentSeparator,
            documentSource ?? string.Empty);
    }

    private sealed class CacheEntry
    {
        public CacheEntry(string key, TrustPolicyTranslationResult result)
        {
            Key = key;
            Result = result;
        }

        public string Key { get; }

        public TrustPolicyTranslationResult Result { get; }
    }
}
