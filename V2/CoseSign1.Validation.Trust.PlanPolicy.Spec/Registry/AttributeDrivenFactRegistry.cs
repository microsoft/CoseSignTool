// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Reflection;
using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Discovery-driven <see cref="IFactRegistry"/> that builds its mapping by reflecting over the
/// supplied assemblies for types decorated with <see cref="TrustFactIdAttribute"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is the Phase 3 (<c>tp-fact-registry</c>) replacement for the hand-rolled
/// <see cref="StaticFactRegistry"/>. Co-locating the id with the fact (design decision D2)
/// means new facts no longer need a sibling registry edit — adding the attribute to the type
/// is sufficient for any registry consumer to pick it up at startup.
/// </para>
/// <para>
/// Behaviour:
/// <list type="bullet">
///   <item>A duplicate id (two CLR types decorated with the same <see cref="TrustFactIdAttribute"/>)
///         throws <see cref="ArgumentException"/> with diagnostic code <c>TPX300</c> at construction.</item>
///   <item>Types missing the attribute are silently ignored — fact authors that opt out of the
///         registry stay invisible to the spec compiler / translator infrastructure.</item>
///   <item>The same id may NOT be reported by two distinct assemblies; the duplicate-id check
///         is global across the supplied scan set.</item>
///   <item>Reflection results are materialised eagerly so the bidirectional map is fixed at
///         construction time and lookups never trigger reflection on the hot path.</item>
/// </list>
/// </para>
/// </remarks>
public sealed class AttributeDrivenFactRegistry : IFactRegistry
{
    private readonly IReadOnlyDictionary<string, Type> IdToType;
    private readonly IReadOnlyDictionary<Type, string> TypeToId;
    private readonly IReadOnlySet<string> Ids;

    /// <summary>
    /// Initializes a new instance of the <see cref="AttributeDrivenFactRegistry"/> class by
    /// scanning the supplied assemblies for types decorated with <see cref="TrustFactIdAttribute"/>.
    /// </summary>
    /// <param name="scanAssemblies">Assemblies to reflect over. Must not be null and must not contain null entries.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="scanAssemblies"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="scanAssemblies"/> contains a null entry, when the same fact id
    /// is declared on two different CLR types (diagnostic <c>TPX300</c>), or when a tagged
    /// CLR type appears under two different ids.
    /// </exception>
    public AttributeDrivenFactRegistry(IEnumerable<Assembly> scanAssemblies)
    {
        Cose.Abstractions.Guard.ThrowIfNull(scanAssemblies);

        // Materialise once so a deferred enumerable can't surprise us.
        var assemblies = scanAssemblies as IReadOnlyList<Assembly> ?? scanAssemblies.ToList();

        var idToType = new Dictionary<string, Type>(StringComparer.Ordinal);
        var typeToId = new Dictionary<Type, string>();

        foreach (Assembly asm in assemblies)
        {
            if (asm is null)
            {
                throw new ArgumentException(ClassStrings.ErrAttributeDrivenScanAssembliesNull, nameof(scanAssemblies));
            }

            foreach (Type type in SafeGetTypes(asm))
            {
                TrustFactIdAttribute? attr = type.GetCustomAttribute<TrustFactIdAttribute>(inherit: false);
                if (attr is null)
                {
                    continue;
                }

                string id = attr.Id;

                if (idToType.TryGetValue(id, out Type? existing))
                {
                    if (existing != type)
                    {
                        throw new ArgumentException(
                            string.Format(
                                CultureInfo.InvariantCulture,
                                ClassStrings.ErrTrustFactIdDuplicateFormat,
                                id,
                                existing.FullName,
                                type.FullName),
                            nameof(scanAssemblies));
                    }

                    // Same type observed twice (assembly listed twice in the scan set) — idempotent.
                    continue;
                }

                if (typeToId.TryGetValue(type, out string? existingId))
                {
                    // Defensive: AttributeUsage.AllowMultiple=false makes this unreachable today
                    // through the public attribute, but a future change to the attribute could
                    // regress this; keep the invariant explicit so registry consumers can trust
                    // the bidirection.
                    throw new ArgumentException(
                        string.Format(
                            CultureInfo.InvariantCulture,
                            ClassStrings.ErrDuplicateFactClrTypeFormat,
                            type.FullName,
                            existingId),
                        nameof(scanAssemblies));
                }

                idToType[id] = type;
                typeToId[type] = id;
            }
        }

        IdToType = idToType;
        TypeToId = typeToId;
        Ids = new SortedSet<string>(idToType.Keys, StringComparer.Ordinal);
    }

    /// <summary>
    /// Builds an <see cref="AttributeDrivenFactRegistry"/> from every assembly currently loaded
    /// in the default <see cref="AppDomain"/> whose simple name starts with <c>CoseSign1.</c>.
    /// </summary>
    /// <returns>A registry mapping every discovered (id, type) pair.</returns>
    /// <remarks>
    /// Restricting the scan to <c>CoseSign1.*</c> assemblies avoids reflecting over the entire
    /// host process — both for cost and to make the discovered surface deterministic in
    /// environments where unrelated assemblies are loaded (e.g., test runners).
    /// </remarks>
    public static AttributeDrivenFactRegistry FromLoadedAssemblies()
    {
        // Explicitly capture the three known fact-host assemblies via Type.Assembly. This is
        // stronger than `_ = typeof(...)` because the JIT cannot elide an Assembly value that is
        // observed in a collection. It also guarantees that even if the host hasn't already
        // touched a fact type, the registry sees every shipped fact pack.
        var explicitAssemblies = new HashSet<Assembly>
        {
            typeof(IMessageFact).Assembly,
            typeof(CoseSign1.Certificates.Trust.Facts.X509ChainTrustedFact).Assembly,
            typeof(CoseSign1.Transparent.MST.Trust.MstReceiptPresentFact).Assembly,
        };

        Assembly[] loaded = AppDomain.CurrentDomain.GetAssemblies();
        foreach (Assembly asm in loaded)
        {
            string? simpleName = asm.GetName().Name;
            if (simpleName is not null && simpleName.StartsWith(ClassStrings.AttributeDrivenAssemblyPrefix, StringComparison.Ordinal))
            {
                explicitAssemblies.Add(asm);
            }
        }

        return new AttributeDrivenFactRegistry(explicitAssemblies);
    }

    /// <inheritdoc />
    public IReadOnlySet<string> AllFactIds => Ids;

    /// <inheritdoc />
    public bool TryGetFactType(string factId, [NotNullWhen(true)] out Type? clrType)
    {
        Cose.Abstractions.Guard.ThrowIfNull(factId);
        return IdToType.TryGetValue(factId, out clrType);
    }

    /// <inheritdoc />
    public bool TryGetFactId(Type clrType, [NotNullWhen(true)] out string? factId)
    {
        Cose.Abstractions.Guard.ThrowIfNull(clrType);
        return TypeToId.TryGetValue(clrType, out factId);
    }

    private static Type[] SafeGetTypes(Assembly asm)
    {
        try
        {
            return asm.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            // Recover the types that did load. Unloadable types simply don't participate in the
            // registry — they could not have been a tagged fact in any case (load failure means
            // the attribute would never have been observable).
            return ex.Types
                .Where(static t => t is not null)
                .Select(static t => t!)
                .ToArray();
        }
    }
}
