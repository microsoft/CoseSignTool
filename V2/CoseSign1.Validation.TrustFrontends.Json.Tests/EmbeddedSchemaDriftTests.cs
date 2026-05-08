// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json.Tests;

using System.IO;
using System.Reflection;

[TestFixture]
[Category("EmbeddedSchema")]
public sealed class EmbeddedSchemaDriftTests
{
    [Test]
    public void EmbeddedSchema_BytesEqualOnDiskFile_NoDrift()
    {
        // Locate the on-disk schema by walking up from the test assembly to the repo root.
        string startDir = Path.GetDirectoryName(typeof(EmbeddedSchemaDriftTests).Assembly.Location)!;
        DirectoryInfo? d = new(startDir);
        string? schemaPath = null;
        while (d is not null)
        {
            string candidate = Path.Combine(d.FullName, "schemas", "cose-tp", "v1.json");
            if (File.Exists(candidate))
            {
                schemaPath = candidate;
                break;
            }

            d = d.Parent;
        }

        Assert.That(schemaPath, Is.Not.Null, "Could not locate V2/schemas/cose-tp/v1.json walking up from the test assembly.");

        byte[] onDisk = File.ReadAllBytes(schemaPath!);
        byte[] embedded = CoseTpJsonFrontend.GetEmbeddedSchemaBytes();

        Assert.That(embedded, Is.EqualTo(onDisk),
            "Embedded schema resource has drifted from V2/schemas/cose-tp/v1.json. " +
            "Rebuild the frontend project after editing the schema so the manifest resource refreshes.");
    }

    [Test]
    public void EmbeddedSchema_GetBytes_IsCachedSecondCallReturnsSame()
    {
        byte[] first = CoseTpJsonFrontend.GetEmbeddedSchemaBytes();
        byte[] second = CoseTpJsonFrontend.GetEmbeddedSchemaBytes();
        Assert.That(second, Is.SameAs(first), "The embedded schema bytes should be cached after first access.");
    }

    [Test]
    public void EmbeddedSchema_ResourceName_MatchesPublicConstant()
    {
        Assembly asm = typeof(CoseTpJsonFrontend).Assembly;
        Assert.That(asm.GetManifestResourceNames(), Has.Member(CoseTpJsonFrontend.EmbeddedSchemaResourceName));
    }
}
