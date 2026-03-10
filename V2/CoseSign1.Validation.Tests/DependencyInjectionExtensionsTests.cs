// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using CoseSign1.Validation.Trust.Facts.Producers;
using Microsoft.Extensions.DependencyInjection;

[TestFixture]
[Category("Validation")]
public class DependencyInjectionExtensionsTests
{
    [Test]
    public void ConfigureCoseValidation_NullServices_ThrowsArgumentNullException()
    {
        IServiceCollection? services = null;
        Assert.Throws<ArgumentNullException>(() => services!.ConfigureCoseValidation());
    }

    [Test]
    public void ConfigureCoseValidation_RegistersCoreMessageFactsTrustPack()
    {
        var services = new ServiceCollection();

        _ = services.ConfigureCoseValidation();

        Assert.That(
            services.Any(sd => sd.ServiceType == typeof(ITrustPack) && sd.ImplementationType == typeof(CoreMessageFactsProducer)),
            Is.True);
    }

    [Test]
    public void EnableMessageFacts_WhenCalledMultipleTimes_DoesNotRegisterDuplicateTrustPack()
    {
        var services = new ServiceCollection();

        var builder = services.ConfigureCoseValidation();
        _ = builder.EnableMessageFacts();
        _ = builder.EnableMessageFacts();

        var count = services.Count(sd => sd.ServiceType == typeof(ITrustPack) && sd.ImplementationType == typeof(CoreMessageFactsProducer));
        Assert.That(count, Is.EqualTo(1));
    }

    [Test]
    public void EnableMessageFacts_NullBuilder_ThrowsArgumentNullException()
    {
        ICoseValidationBuilder? builder = null;
        Assert.Throws<ArgumentNullException>(() => builder!.EnableMessageFacts());
    }
}
