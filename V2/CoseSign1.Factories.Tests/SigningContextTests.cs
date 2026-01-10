// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories.Tests;

[TestFixture]
public class SigningContextTests
{
    [Test]
    public void Constructor_WithStream_SetsHasStreamAndExposesPayloadStream()
    {
        using var stream = new MemoryStream(new byte[] { 1, 2, 3 });
        var ctx = new SigningContext(stream, "application/octet-stream");

        Assert.That(ctx.HasStream, Is.True);
        Assert.That(ctx.PayloadStream, Is.SameAs(stream));

        var ex = Assert.Throws<InvalidOperationException>(() => _ = ctx.PayloadBytes);
        Assert.That(ex!.Message, Does.Contain("Context contains stream payload"));
    }

    [Test]
    public void Constructor_WithBytes_SetsHasStreamFalseAndExposesPayloadBytes()
    {
        var payload = new byte[] { 4, 5, 6 };
        var ctx = new SigningContext(payload, "application/octet-stream");

        Assert.That(ctx.HasStream, Is.False);
        Assert.That(ctx.PayloadBytes.ToArray(), Is.EqualTo(payload));

        var ex = Assert.Throws<InvalidOperationException>(() => _ = ctx.PayloadStream);
        Assert.That(ex!.Message, Does.Contain("Context contains byte payload"));
    }

    [Test]
    public void Constructor_WithNullStream_ThrowsArgumentNullException()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new SigningContext((Stream)null!, "application/octet-stream"));
        Assert.That(ex!.ParamName, Is.EqualTo("payloadStream"));
    }
}
