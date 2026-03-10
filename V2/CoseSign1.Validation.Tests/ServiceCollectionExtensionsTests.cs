// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Validation.PostSignature;
using CoseSign1.Validation.Trust.Facts.Producers;
using Microsoft.Extensions.DependencyInjection;

[TestFixture]
[Category("Validation")]
public sealed class ServiceCollectionExtensionsTests
{
    [Test]
    public void ConfigureCoseValidation_NullServices_ThrowsArgumentNullException()
    {
        Assert.That(() => _ = Microsoft.Extensions.DependencyInjection.CoseValidationServiceCollectionExtensions.ConfigureCoseValidation(null!), Throws.ArgumentNullException);
    }

    [Test]
    public void ConfigureCoseValidation_IsIdempotent_ForCoreRegistrations()
    {
        var services = new ServiceCollection();

        _ = services.ConfigureCoseValidation();
        _ = services.ConfigureCoseValidation();

        var trustPackCount = services.Count(sd => sd.ServiceType == typeof(CoseSign1.Validation.Trust.ITrustPack)
            && sd.ImplementationType == typeof(CoreMessageFactsProducer));

        var postValidatorCount = services.Count(sd => sd.ServiceType == typeof(CoseSign1.Validation.Interfaces.IPostSignatureValidator)
            && sd.ImplementationType == typeof(IndirectSignatureValidator));

        var validatorFactoryCount = services.Count(sd => sd.ServiceType == typeof(CoseSign1.Validation.DependencyInjection.ICoseSign1ValidatorFactory));

        Assert.Multiple(() =>
        {
            Assert.That(trustPackCount, Is.EqualTo(1));
            Assert.That(postValidatorCount, Is.EqualTo(1));
            Assert.That(validatorFactoryCount, Is.EqualTo(1));
        });
    }

    [Test]
    public void EnableMessageFacts_NullBuilder_ThrowsArgumentNullException()
    {
        Assert.That(() => _ = MessageFactsValidationBuilderExtensions.EnableMessageFacts(null!), Throws.ArgumentNullException);
    }
}
