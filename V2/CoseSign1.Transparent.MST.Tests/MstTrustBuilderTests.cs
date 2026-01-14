// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests;

using CoseSign1.Transparent.MST.Trust;
using CoseSign1.Validation.Trust;
using Microsoft.Extensions.DependencyInjection;

[TestFixture]
public class MstTrustBuilderTests
{
    [Test]
    public void VerifyReceipts_NullEndpoint_ThrowsArgumentNullException()
    {
        var builder = new MstTrustBuilder();
        Assert.Throws<ArgumentNullException>(() => builder.VerifyReceipts(null!));
    }

    [Test]
    public void VerifyReceipts_SetsOptions()
    {
        var endpoint = new Uri("https://mst.example.test/");
        var builder = new MstTrustBuilder();

        _ = builder.VerifyReceipts(endpoint);

        Assert.That(builder.Options.VerifyReceipts, Is.True);
        Assert.That(builder.Options.Endpoint, Is.EqualTo(endpoint));
    }

    [Test]
    public void OfflineOnly_SetsOptions()
    {
        var builder = new MstTrustBuilder();

        _ = builder.OfflineOnly();

        Assert.That(builder.Options.OfflineOnly, Is.True);
    }

    [Test]
    public void EnableMstTrust_RegistersOptionsAndTrustPack()
    {
        var services = new ServiceCollection();
        var builder = services.ConfigureCoseValidation();

        _ = builder.EnableMstTrust(b => b.VerifyReceipts(new Uri("https://mst.example.test/")).OfflineOnly());

        Assert.That(services.Any(sd => sd.ServiceType == typeof(MstTrustOptions)), Is.True);
        Assert.That(services.Any(sd => sd.ServiceType == typeof(ITrustPack) && sd.ImplementationType == typeof(MstTrustPack)), Is.True);
    }
}
