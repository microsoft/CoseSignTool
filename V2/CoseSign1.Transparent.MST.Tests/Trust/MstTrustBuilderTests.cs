// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Tests.Trust;

using CoseSign1.Transparent.MST.Trust;

[TestFixture]
public sealed class MstTrustBuilderTests
{
    [Test]
    public void VerifyReceipts_SetsVerifyReceipts()
    {
        var builder = new MstTrustBuilder();

        builder.VerifyReceipts();

        Assert.That(builder.Options.VerifyReceipts, Is.True);
        Assert.That(builder.Options.Endpoint, Is.Null);
    }

    [Test]
    public void VerifyReceipts_WithEndpoint_SetsVerifyReceiptsAndEndpoint()
    {
        var builder = new MstTrustBuilder();
        var endpoint = new Uri("https://mst.example.com");

        builder.VerifyReceipts(endpoint);

        Assert.That(builder.Options.VerifyReceipts, Is.True);
        Assert.That(builder.Options.Endpoint, Is.EqualTo(endpoint));
    }

    [Test]
    public void VerifyReceipts_WithNullEndpoint_ThrowsArgumentNullException()
    {
        var builder = new MstTrustBuilder();

        Assert.Throws<ArgumentNullException>(() => builder.VerifyReceipts(null!));
    }

    [Test]
    public void RequireIssuerHost_WithValidValue_SetsAuthorizedDomains()
    {
        var builder = new MstTrustBuilder();

        builder.RequireIssuerHost("ledger.example.com");

        Assert.That(builder.Options.AuthorizedDomains, Is.Not.Null);
        Assert.That(builder.Options.AuthorizedDomains, Has.Count.EqualTo(1));
        Assert.That(builder.Options.AuthorizedDomains![0], Is.EqualTo("ledger.example.com"));
    }

    [Test]
    public void RequireIssuerHost_WithWhitespace_ThrowsArgumentException()
    {
        var builder = new MstTrustBuilder();

        Assert.Throws<ArgumentException>(() => builder.RequireIssuerHost("  "));
    }

    [Test]
    public void UseOfflineTrustedJwksJson_SetsOfflineOnlyAndPinnedJwks()
    {
        var builder = new MstTrustBuilder();
        const string jwksJson = "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\"}]}";

        builder.UseOfflineTrustedJwksJson(jwksJson);

        Assert.That(builder.Options.VerifyReceipts, Is.True);
        Assert.That(builder.Options.OfflineOnly, Is.True);
        Assert.That(builder.Options.HasOfflineKeys, Is.True);
        Assert.That(builder.Options.OfflineTrustedJwksJson, Is.EqualTo(jwksJson));
    }

    [Test]
    public void UseOfflineTrustedJwksJson_WithWhitespace_ThrowsArgumentException()
    {
        var builder = new MstTrustBuilder();

        Assert.Throws<ArgumentException>(() => builder.UseOfflineTrustedJwksJson("\t"));
    }

    [Test]
    public void OfflineOnly_SetsOfflineOnly()
    {
        var builder = new MstTrustBuilder();

        builder.OfflineOnly();

        Assert.That(builder.Options.OfflineOnly, Is.True);
    }
}
