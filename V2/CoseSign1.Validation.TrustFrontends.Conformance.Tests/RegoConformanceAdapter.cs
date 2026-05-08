// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.TrustFrontends.Json;
using CoseSign1.Validation.TrustFrontends.Rego;

/// <summary>
/// Conformance adapter for <c>cose-tp-rego/v1</c>. Mirrors <c>JsonConformanceAdapter</c>:
/// loads on-disk fixtures from <c>fixtures/rego/</c> (alongside the test assembly), routes
/// translation through <see cref="CoseTpRegoFrontend"/>, and exposes a fixture-name set
/// the cross-frontend equivalence harness keys off.
/// </summary>
internal sealed class RegoConformanceAdapter : IConformanceFrontendAdapter<RegoDocument>
{
    private const string FrontendFolderName = "rego";
    private const string FixtureExtension = ".coseTrustPolicy.rego";

    private readonly CoseTpRegoFrontend FrontendInstance;
    private readonly Dictionary<string, string> NameToPath;

    public RegoConformanceAdapter()
        : this(new CoseTpRegoFrontend(new CoseTpJsonFrontend()))
    {
    }

    internal RegoConformanceAdapter(CoseTpRegoFrontend frontend)
    {
        FrontendInstance = frontend;
        NameToPath = DiscoverFixtures();
    }

    /// <inheritdoc />
    public string FrontendId => CoseTpRegoOptions.FrontendId;

    /// <inheritdoc />
    public IReadOnlySet<string> ProvidedFixtureNames
    {
        get
        {
            HashSet<string> names = new(StringComparer.Ordinal);
            foreach (string key in NameToPath.Keys)
            {
                names.Add(key);
            }

            return names;
        }
    }

    /// <inheritdoc />
    public RegoDocument? LoadFixture(string name)
    {
        string text = LoadFixtureText(name);
        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        return CoseTpRegoFrontend.TryParse(text, name, diagnostics);
    }

    /// <inheritdoc />
    public string LoadFixtureText(string name)
    {
        if (!NameToPath.TryGetValue(name, out string? path))
        {
            throw new FileNotFoundException(string.Format(
                System.Globalization.CultureInfo.InvariantCulture,
                "Conformance fixture '{0}' not found in the rego adapter's fixture set.",
                name));
        }

        return File.ReadAllText(path);
    }

    /// <inheritdoc />
    public TrustPolicyTranslationResult Translate(RegoDocument document, TrustPolicyTranslationContext ctx)
        => FrontendInstance.Translate(document, ctx);

    /// <inheritdoc />
    public TrustPolicyTranslationResult TranslateText(string fixtureText, TrustPolicyTranslationContext ctx)
        => FrontendInstance.TranslateText(fixtureText, ctx);

    private static Dictionary<string, string> DiscoverFixtures()
    {
        // Same on-disk layout convention as the JSON adapter: fixtures/rego/<logical>.<ext>.
        // The logical name maps 1:1 to the JSON adapter's logical name when the fixture
        // expresses the same logical policy — that's what makes cross-frontend equivalence
        // a property of fixture-naming alone.
        string assemblyDir = Path.GetDirectoryName(typeof(RegoConformanceAdapter).Assembly.Location)!;
        string root = Path.Combine(assemblyDir, "fixtures", FrontendFolderName);
        if (!Directory.Exists(root))
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        Dictionary<string, string> map = new(StringComparer.Ordinal);
        foreach (string file in Directory.EnumerateFiles(root, "*" + FixtureExtension, SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            if (!relative.EndsWith(FixtureExtension, StringComparison.Ordinal))
            {
                continue;
            }

            string logicalName = relative.Substring(0, relative.Length - FixtureExtension.Length);
            map[logicalName] = file;
        }

        return map;
    }
}
