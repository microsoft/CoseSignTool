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
}
