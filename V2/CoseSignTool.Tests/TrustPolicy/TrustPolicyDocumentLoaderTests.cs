// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.TrustPolicy;

using System;
using System.IO;
using CoseSignTool.TrustPolicy;
using Microsoft.Extensions.DependencyInjection;

[TestFixture]
[NonParallelizable]
public sealed class TrustPolicyDocumentLoaderTests
{
    private string TempPath = string.Empty;

    [SetUp]
    public void SetUp()
    {
        TempPath = Path.Combine(Path.GetTempPath(), $"tp-{Guid.NewGuid():N}.coseTrustPolicy.json");
    }

    [TearDown]
    public void TearDown()
    {
        try
        {
            if (File.Exists(TempPath))
            {
                File.Delete(TempPath);
            }
        }
        catch
        {
            // Best effort.
        }
    }

    private static IServiceProvider BuildServices()
    {
        var services = new ServiceCollection();
        services.AddAttributeDrivenFactRegistry();
        return services.BuildServiceProvider();
    }

    [Test]
    public void LoadAndCompile_NullPath_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            TrustPolicyDocumentLoader.LoadAndCompile(null!, Array.Empty<string>(), BuildServices(), TextWriter.Null));
    }

    [Test]
    public void LoadAndCompile_NullParams_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            TrustPolicyDocumentLoader.LoadAndCompile("path", null!, BuildServices(), TextWriter.Null));
    }

    [Test]
    public void LoadAndCompile_NullServices_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            TrustPolicyDocumentLoader.LoadAndCompile("path", Array.Empty<string>(), null!, TextWriter.Null));
    }

    [Test]
    public void LoadAndCompile_NullErrorWriter_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            TrustPolicyDocumentLoader.LoadAndCompile("path", Array.Empty<string>(), BuildServices(), null!));
    }

    [Test]
    public void LoadAndCompile_FileMissing_WritesErrorAndReturnsNull()
    {
        var sw = new StringWriter();
        var result = TrustPolicyDocumentLoader.LoadAndCompile(
            Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".missing"),
            Array.Empty<string>(),
            BuildServices(),
            sw);

        Assert.That(result, Is.Null);
        Assert.That(sw.ToString(), Does.Contain("Trust-policy file not found"));
    }

    [Test]
    public void LoadAndCompile_AllowAllDocument_CompilesSuccessfully()
    {
        File.WriteAllText(TempPath, """{"message":{"allow_all":true}}""");
        var sw = new StringWriter();
        var result = TrustPolicyDocumentLoader.LoadAndCompile(TempPath, Array.Empty<string>(), BuildServices(), sw);
        Assert.That(result, Is.Not.Null, sw.ToString());
    }

    [Test]
    public void LoadAndCompile_FileUriScheme_IsSupported()
    {
        File.WriteAllText(TempPath, """{"message":{"allow_all":true}}""");
        var sw = new StringWriter();
        var fileUri = new Uri(TempPath).AbsoluteUri;
        var result = TrustPolicyDocumentLoader.LoadAndCompile(fileUri, Array.Empty<string>(), BuildServices(), sw);
        Assert.That(result, Is.Not.Null, sw.ToString());
    }

    [Test]
    public void LoadAndCompile_MalformedJson_WritesDiagnosticsAndReturnsNull()
    {
        File.WriteAllText(TempPath, "{not json");
        var sw = new StringWriter();
        var result = TrustPolicyDocumentLoader.LoadAndCompile(TempPath, Array.Empty<string>(), BuildServices(), sw);
        Assert.That(result, Is.Null);
        Assert.That(sw.ToString(), Does.Contain("translation failed"));
    }

    [Test]
    public void LoadAndCompile_UnknownFactWithRegistry_FailsWithTpx200()
    {
        File.WriteAllText(TempPath,
            """{"primary_signing_key":{"fact":"definitely-not-a-real-fact/v1","predicate":{"x":1}}}""");
        var sw = new StringWriter();
        var result = TrustPolicyDocumentLoader.LoadAndCompile(TempPath, Array.Empty<string>(), BuildServices(), sw);
        Assert.That(result, Is.Null);
        Assert.That(sw.ToString(), Does.Contain("TPX200"));
    }

    [Test]
    public void LoadAndCompile_UnboundParameter_FailsWithTpx400()
    {
        File.WriteAllText(TempPath,
            """{"primary_signing_key":{"fact":"x509-chain-trusted/v1","predicate":{"is_trusted":{"$param":"unbound"}}}}""");
        var sw = new StringWriter();
        var result = TrustPolicyDocumentLoader.LoadAndCompile(TempPath, Array.Empty<string>(), BuildServices(), sw);
        Assert.That(result, Is.Null);
        Assert.That(sw.ToString(), Does.Contain("TPX400"));
    }

    [Test]
    public void LoadAndCompile_BoundParameter_CompilesSuccessfully()
    {
        File.WriteAllText(TempPath,
            """{"primary_signing_key":{"fact":"x509-chain-trusted/v1","predicate":{"is_trusted":{"$param":"trust"}}}}""");
        var sw = new StringWriter();
        var result = TrustPolicyDocumentLoader.LoadAndCompile(TempPath, new[] { "trust=true" }, BuildServices(), sw);
        Assert.That(result, Is.Not.Null, sw.ToString());
    }

    [Test]
    public void LoadAndCompile_MalformedParam_WritesError()
    {
        File.WriteAllText(TempPath, """{"message":{"allow_all":true}}""");
        var sw = new StringWriter();
        var result = TrustPolicyDocumentLoader.LoadAndCompile(TempPath, new[] { "no_equals_sign" }, BuildServices(), sw);
        Assert.That(result, Is.Null);
        Assert.That(sw.ToString(), Does.Contain("expected 'name=jsonValue'"));
    }

    [Test]
    public void LoadAndCompile_MalformedParamJsonValue_WritesError()
    {
        File.WriteAllText(TempPath, """{"message":{"allow_all":true}}""");
        var sw = new StringWriter();
        var result = TrustPolicyDocumentLoader.LoadAndCompile(TempPath, new[] { "x={not_json" }, BuildServices(), sw);
        Assert.That(result, Is.Null);
        Assert.That(sw.ToString(), Does.Contain("Invalid --trust-policy-param"));
    }

    [Test]
    public void LoadAndCompile_HttpUrlUnreachable_WritesErrorAndReturnsNull()
    {
        var sw = new StringWriter();
        var result = TrustPolicyDocumentLoader.LoadAndCompile("http://localhost:1/missing", Array.Empty<string>(), BuildServices(), sw);
        Assert.That(result, Is.Null);
        Assert.That(sw.ToString(), Does.Contain("Failed to fetch trust-policy"));
    }

    [Test]
    public void LoadAndCompile_RegistryAbsent_FallsBackToLoadedAssemblies()
    {
        File.WriteAllText(TempPath, """{"message":{"allow_all":true}}""");
        var services = new ServiceCollection().BuildServiceProvider();
        var sw = new StringWriter();
        var result = TrustPolicyDocumentLoader.LoadAndCompile(TempPath, Array.Empty<string>(), services, sw);
        Assert.That(result, Is.Not.Null, sw.ToString());
    }

    [Test]
    public void SelectFrontend_RegoExtension_RoutesToRego()
    {
        Assert.That(TrustPolicyDocumentLoader.SelectFrontend("policy.coseTrustPolicy.rego", string.Empty), Is.True);
    }

    [Test]
    public void SelectFrontend_JsonExtension_RoutesToJson()
    {
        Assert.That(TrustPolicyDocumentLoader.SelectFrontend("policy.coseTrustPolicy.json", string.Empty), Is.False);
    }

    [Test]
    public void SelectFrontend_DocumentLeadingPackageMarker_RoutesToRego()
    {
        const string text = "package cose_trust_policy\n\npolicy := {}\n";
        Assert.That(TrustPolicyDocumentLoader.SelectFrontend("policy.txt", text), Is.True);
    }

    [Test]
    public void SelectFrontend_HeaderCommentBeforePackage_RoutesToRego()
    {
        // Comments and blank lines before the package declaration should not mask the
        // marker.
        const string text = "# my-validation\n\npackage cose_trust_policy\n";
        Assert.That(TrustPolicyDocumentLoader.SelectFrontend("policy.txt", text), Is.True);
    }

    [Test]
    public void SelectFrontend_DocumentWithoutMarker_RoutesToJson()
    {
        const string text = """{"frontend":"cose-tp-json/v1"}""";
        Assert.That(TrustPolicyDocumentLoader.SelectFrontend("policy.txt", text), Is.False);
    }

    [Test]
    public void SelectFrontend_EmptyText_RoutesToJson()
    {
        Assert.That(TrustPolicyDocumentLoader.SelectFrontend("policy.txt", string.Empty), Is.False);
    }

    [Test]
    public void SelectFrontend_OnlyCommentsAndBlanks_RoutesToJson()
    {
        const string text = "# only a comment\n\n# another\n";
        Assert.That(TrustPolicyDocumentLoader.SelectFrontend("policy.txt", text), Is.False);
    }

    [Test]
    public void LoadAndCompile_RegoFileExtension_LoadsViaRegoFrontend()
    {
        string regoPath = Path.Combine(Path.GetTempPath(), $"tp-{Guid.NewGuid():N}.coseTrustPolicy.rego");
        try
        {
            File.WriteAllText(regoPath, """
                package cose_trust_policy

                policy := {
                    "primary_signing_key": {
                        "fact": "x509-chain-trusted/v1",
                        "predicate": {"is_trusted": true}
                    }
                }
                """);
            var sw = new StringWriter();
            var result = TrustPolicyDocumentLoader.LoadAndCompile(regoPath, Array.Empty<string>(), BuildServices(), sw);
            Assert.That(result, Is.Not.Null, sw.ToString());
        }
        finally
        {
            try
            {
                if (File.Exists(regoPath))
                {
                    File.Delete(regoPath);
                }
            }
            catch
            {
                // Best effort.
            }
        }
    }

    [Test]
    public void LoadAndCompile_RegoDocumentRejected_ReportsTPX300Diagnostic()
    {
        string regoPath = Path.Combine(Path.GetTempPath(), $"tp-{Guid.NewGuid():N}.coseTrustPolicy.rego");
        try
        {
            File.WriteAllText(regoPath, """
                package cose_trust_policy

                policy := {
                    "primary_signing_key": {
                        "fact": "x509-chain-trusted/v1",
                        "predicate": {"value": http.send({"url": "https://example"})}
                    }
                }
                """);
            var sw = new StringWriter();
            var result = TrustPolicyDocumentLoader.LoadAndCompile(regoPath, Array.Empty<string>(), BuildServices(), sw);
            Assert.That(result, Is.Null);
            Assert.That(sw.ToString(), Does.Contain("TPX300"));
        }
        finally
        {
            try
            {
                if (File.Exists(regoPath))
                {
                    File.Delete(regoPath);
                }
            }
            catch
            {
                // Best effort.
            }
        }
    }
}
