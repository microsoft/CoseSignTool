// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json.Tests;

using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Compilation;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;
using Microsoft.Extensions.DependencyInjection;

[TestFixture]
[Category("CompileFromSpec")]
public sealed class CompiledTrustPlanFromSpecTests
{
    [Test]
    public void CompileFromSpec_NullSpec_Throws()
    {
        var registry = AttributeDrivenFactRegistry.FromLoadedAssemblies();
        var sp = new ServiceCollection().BuildServiceProvider();
        Assert.Throws<System.ArgumentNullException>(() => CompiledTrustPlanFromSpec.CompileFromSpec(null!, registry, sp));
    }

    [Test]
    public void CompileFromSpec_NullRegistry_Throws()
    {
        var sp = new ServiceCollection().BuildServiceProvider();
        var f = new CoseTpJsonFrontend();
        var r = f.TranslateText("""{"message":{"allow_all":true}}""", new TrustPolicyTranslationContext());
        Assert.That(r.IsSuccess, Is.True);
        Assert.Throws<System.ArgumentNullException>(() => CompiledTrustPlanFromSpec.CompileFromSpec(r.Spec!, null!, sp));
    }

    [Test]
    public void CompileFromSpec_NullServices_Throws()
    {
        var registry = AttributeDrivenFactRegistry.FromLoadedAssemblies();
        var f = new CoseTpJsonFrontend();
        var r = f.TranslateText("""{"message":{"allow_all":true}}""", new TrustPolicyTranslationContext());
        Assert.Throws<System.ArgumentNullException>(() => CompiledTrustPlanFromSpec.CompileFromSpec(r.Spec!, registry, null!));
    }

    [Test]
    public void CompileFromSpec_AllowAllSpec_Compiles()
    {
        var registry = AttributeDrivenFactRegistry.FromLoadedAssemblies();
        var sp = new ServiceCollection().BuildServiceProvider();
        var f = new CoseTpJsonFrontend();
        var r = f.TranslateText("""{"message":{"allow_all":true}}""", new TrustPolicyTranslationContext());

        var plan = CompiledTrustPlanFromSpec.CompileFromSpec(r.Spec!, registry, sp);
        Assert.That(plan, Is.Not.Null);
    }
}
