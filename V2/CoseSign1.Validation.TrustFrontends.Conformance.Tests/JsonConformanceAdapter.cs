// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance.Tests;

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.TrustFrontends.Json;

/// <summary>
/// Conformance adapter for <c>cose-tp-json/v1</c>. Loads on-disk fixtures from the
/// per-frontend folder (<c>fixtures/json/</c> alongside the test assembly) and routes
/// translation through <see cref="CoseTpJsonFrontend"/>.
/// </summary>
internal sealed class JsonConformanceAdapter : IConformanceFrontendAdapter<JsonDocument>
{
    private const string FrontendFolderName = "json";
    private const string MalformedFixtureExtension = ".coseTrustPolicy.malformed.txt";

    private readonly CoseTpJsonFrontend FrontendInstance = new();
    private readonly Dictionary<string, string> NameToPath;

    public JsonConformanceAdapter()
    {
        NameToPath = DiscoverFixtures();
    }

    public string FrontendId => "cose-tp-json/v1";

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

    public JsonDocument? LoadFixture(string name)
    {
        // Schema-failure fixtures intentionally are not parseable JSON, so we surface them
        // via LoadFixtureText only — return null so the conformance suite knows to route
        // through the text overload. We additionally null-out the unknown-fact fixture so
        // Conformance_3's null-document branch is exercised: both translation-via-text and
        // translation-via-document are valid resolutions of the §6.5.10 #3 contract.
        if (name == AssemblyStrings.FixtureSchemaMalformedJson || name == AssemblyStrings.FixtureUntranslatableUnknownFact)
        {
            return null;
        }

        string text = LoadFixtureText(name);
        return JsonDocument.Parse(text, CoseTpJsonOptions.ParseOptions);
    }

    public string LoadFixtureText(string name)
    {
        if (!NameToPath.TryGetValue(name, out string? path))
        {
            throw new FileNotFoundException($"Conformance fixture '{name}' not found in the json adapter's fixture set.");
        }

        return File.ReadAllText(path);
    }

    public TrustPolicyTranslationResult Translate(JsonDocument document, TrustPolicyTranslationContext ctx)
        => FrontendInstance.Translate(document, ctx);

    public TrustPolicyTranslationResult TranslateText(string fixtureText, TrustPolicyTranslationContext ctx)
        => FrontendInstance.TranslateText(fixtureText, ctx);

    private static Dictionary<string, string> DiscoverFixtures()
    {
        // Fixtures live next to the test assembly under fixtures/json/. They are copied at
        // build time via the csproj's <None Include="fixtures\**\*"> item group.
        string assemblyDir = Path.GetDirectoryName(typeof(JsonConformanceAdapter).Assembly.Location)!;
        string root = Path.Combine(assemblyDir, "fixtures", FrontendFolderName);
        if (!Directory.Exists(root))
        {
            return new Dictionary<string, string>(StringComparer.Ordinal);
        }

        Dictionary<string, string> map = new(StringComparer.Ordinal);
        // The on-disk layout matches the logical-name layout exactly: fixtures/json/<logical>.<ext>.
        // For example, the logical name 'facts/x509-chain-trusted_v1.property' lives at
        // 'fixtures/json/facts/x509-chain-trusted_v1.property.coseTrustPolicy.json'.
        DiscoverIn(root, root, ".coseTrustPolicy.json", map);
        DiscoverIn(root, root, MalformedFixtureExtension, map);
        return map;
    }

    private static void DiscoverIn(string root, string current, string extension, Dictionary<string, string> map)
    {
        foreach (string file in Directory.EnumerateFiles(current, "*" + extension, SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            if (!relative.EndsWith(extension, StringComparison.Ordinal))
            {
                continue;
            }

            string logicalName = relative.Substring(0, relative.Length - extension.Length);
            map[logicalName] = file;
        }
    }
}
