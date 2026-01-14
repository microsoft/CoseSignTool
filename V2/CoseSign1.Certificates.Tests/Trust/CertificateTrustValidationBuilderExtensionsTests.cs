// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Trust;

using CoseSign1.Certificates.Trust;
using CoseSign1.Certificates.Trust.Facts.Producers;
using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;

[TestFixture]
public class CertificateTrustValidationBuilderExtensionsTests
{
    [Test]
    public void EnableCertificateTrust_NullBuilder_ThrowsArgumentNullException()
    {
        ICoseValidationBuilder? builder = null;
        Assert.Throws<ArgumentNullException>(() => builder!.EnableCertificateTrust());
    }

    [Test]
    public void EnableCertificateTrust_RegistersOptionsAndTrustPack()
    {
        var services = new ServiceCollection();
        var builder = services.ConfigureCoseValidation();

        _ = builder.EnableCertificateTrust(b =>
        {
            b.UseEmbeddedChainOnly();
        });

        Assert.That(services.Any(sd => sd.ServiceType == typeof(CertificateTrustBuilder.CertificateTrustOptions)), Is.True);
        Assert.That(services.Any(sd => sd.ServiceType == typeof(ITrustPack) && sd.ImplementationType == typeof(X509CertificateTrustPack)), Is.True);
    }
}
