// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.DependencyInjection;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;
using Microsoft.Extensions.DependencyInjection;

[TestFixture]
public class CertificateChainBuilderServiceCollectionExtensionsTests
{
    [Test]
    public void AddCertificateChainBuilders_NullServices_ThrowsArgumentNullException()
    {
        IServiceCollection? services = null;
        Assert.Throws<ArgumentNullException>(() => services!.AddCertificateChainBuilders());
    }

    [Test]
    public void AddCertificateChainBuilders_RegistersX509ChainBuilderAndInterface()
    {
        var services = new ServiceCollection();

        _ = services.AddCertificateChainBuilders();

        var sp = services.BuildServiceProvider();
        var concrete = sp.GetRequiredService<X509ChainBuilder>();
        var iface = sp.GetRequiredService<ICertificateChainBuilder>();

        Assert.That(concrete, Is.Not.Null);
        Assert.That(iface, Is.Not.Null);
        Assert.That(iface, Is.InstanceOf<X509ChainBuilder>());
    }
}
