// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography.Cose;

/// <summary>
/// Tests for <see cref="CoseSign1ValidationOptions"/> and extension methods.
/// </summary>
[TestFixture]
[Category("Validation")]
public class CoseSign1ValidationOptionsTests
{
    #region Constructor and Default Values

    [Test]
    public void Constructor_SetsDefaultValues()
    {
        var options = new CoseSign1ValidationOptions();

        Assert.Multiple(() =>
        {
            Assert.That(options.DetachedPayload, Is.Null);
            Assert.That(options.AssociatedData, Is.Null);
            Assert.That(options.CancellationToken, Is.EqualTo(CancellationToken.None));
            Assert.That(options.CertificateHeaderLocation, Is.EqualTo(CoseHeaderLocation.Protected));
        });
    }

    #endregion

    #region Clone Tests

    [Test]
    public void Clone_CopiesAllProperties()
    {
        var stream = new MemoryStream([1, 2, 3]);
        var associatedData = new ReadOnlyMemory<byte>([4, 5, 6]);
        var cts = new CancellationTokenSource();

        var original = new CoseSign1ValidationOptions
        {
            DetachedPayload = stream,
            AssociatedData = associatedData,
            CancellationToken = cts.Token,
            CertificateHeaderLocation = CoseHeaderLocation.Any
        };

        var clone = original.Clone();

        Assert.Multiple(() =>
        {
            Assert.That(clone.DetachedPayload, Is.SameAs(original.DetachedPayload));
            Assert.That(clone.AssociatedData, Is.EqualTo(original.AssociatedData));
            Assert.That(clone.CancellationToken, Is.EqualTo(original.CancellationToken));
            Assert.That(clone.CertificateHeaderLocation, Is.EqualTo(original.CertificateHeaderLocation));
        });

        cts.Dispose();
        stream.Dispose();
    }

    [Test]
    public void Clone_CreatesIndependentInstance()
    {
        var original = new CoseSign1ValidationOptions
        {
            CertificateHeaderLocation = CoseHeaderLocation.Protected
        };

        var clone = original.Clone();
        clone.CertificateHeaderLocation = CoseHeaderLocation.Any;

        Assert.That(original.CertificateHeaderLocation, Is.EqualTo(CoseHeaderLocation.Protected));
    }

    #endregion

    #region Extension Methods - WithDetachedPayload

    [Test]
    public void WithDetachedPayload_Stream_SetsPayload()
    {
        var options = new CoseSign1ValidationOptions();
        var stream = new MemoryStream([1, 2, 3]);

        var result = options.WithDetachedPayload(stream);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.SameAs(options));
            Assert.That(options.DetachedPayload, Is.SameAs(stream));
        });

        stream.Dispose();
    }

    [Test]
    public void WithDetachedPayload_Stream_NullOptions_ThrowsArgumentNullException()
    {
        CoseSign1ValidationOptions? options = null;

        Assert.Throws<ArgumentNullException>(() => options!.WithDetachedPayload(new MemoryStream()));
    }

    [Test]
    public void WithDetachedPayload_ByteArray_SetsPayload()
    {
        var options = new CoseSign1ValidationOptions();
        var payload = new byte[] { 1, 2, 3 };

        var result = options.WithDetachedPayload(payload);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.SameAs(options));
            Assert.That(options.DetachedPayload, Is.Not.Null);
        });

        // Read the content to verify
        options.DetachedPayload!.Position = 0;
        var buffer = new byte[3];
        _ = options.DetachedPayload.ReadAtLeast(buffer, 3);
        Assert.That(buffer, Is.EqualTo(payload));
    }

    [Test]
    public void WithDetachedPayload_ByteArray_NullOptions_ThrowsArgumentNullException()
    {
        CoseSign1ValidationOptions? options = null;

        Assert.Throws<ArgumentNullException>(() => options!.WithDetachedPayload(new byte[] { 1 }));
    }

    [Test]
    public void WithDetachedPayload_ByteArray_NullPayload_ThrowsArgumentNullException()
    {
        var options = new CoseSign1ValidationOptions();

        Assert.Throws<ArgumentNullException>(() => options.WithDetachedPayload((byte[])null!));
    }

    [Test]
    public void WithDetachedPayload_ReadOnlyMemory_SetsPayload()
    {
        var options = new CoseSign1ValidationOptions();
        var payload = new ReadOnlyMemory<byte>([1, 2, 3]);

        var result = options.WithDetachedPayload(payload);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.SameAs(options));
            Assert.That(options.DetachedPayload, Is.Not.Null);
        });
    }

    [Test]
    public void WithDetachedPayload_ReadOnlyMemory_NullOptions_ThrowsArgumentNullException()
    {
        CoseSign1ValidationOptions? options = null;

        Assert.Throws<ArgumentNullException>(() => options!.WithDetachedPayload(new ReadOnlyMemory<byte>([1])));
    }

    #endregion

    #region Extension Methods - WithAssociatedData

    [Test]
    public void WithAssociatedData_ReadOnlyMemory_SetsData()
    {
        var options = new CoseSign1ValidationOptions();
        var data = new ReadOnlyMemory<byte>([1, 2, 3]);

        var result = options.WithAssociatedData(data);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.SameAs(options));
            Assert.That(options.AssociatedData, Is.EqualTo(data));
        });
    }

    [Test]
    public void WithAssociatedData_ReadOnlyMemory_NullOptions_ThrowsArgumentNullException()
    {
        CoseSign1ValidationOptions? options = null;

        Assert.Throws<ArgumentNullException>(() => options!.WithAssociatedData(new ReadOnlyMemory<byte>([1])));
    }

    [Test]
    public void WithAssociatedData_ByteArray_SetsData()
    {
        var options = new CoseSign1ValidationOptions();
        var data = new byte[] { 1, 2, 3 };

        var result = options.WithAssociatedData(data);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.SameAs(options));
            Assert.That(options.AssociatedData!.Value.ToArray(), Is.EqualTo(data));
        });
    }

    [Test]
    public void WithAssociatedData_ByteArray_NullOptions_ThrowsArgumentNullException()
    {
        CoseSign1ValidationOptions? options = null;

        Assert.Throws<ArgumentNullException>(() => options!.WithAssociatedData(new byte[] { 1 }));
    }

    [Test]
    public void WithAssociatedData_ByteArray_NullData_ThrowsArgumentNullException()
    {
        var options = new CoseSign1ValidationOptions();

        Assert.Throws<ArgumentNullException>(() => options.WithAssociatedData((byte[])null!));
    }

    #endregion

    #region Extension Methods - WithCancellationToken

    [Test]
    public void WithCancellationToken_SetsToken()
    {
        var options = new CoseSign1ValidationOptions();
        using var cts = new CancellationTokenSource();

        var result = options.WithCancellationToken(cts.Token);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.SameAs(options));
            Assert.That(options.CancellationToken, Is.EqualTo(cts.Token));
        });
    }

    [Test]
    public void WithCancellationToken_NullOptions_ThrowsArgumentNullException()
    {
        CoseSign1ValidationOptions? options = null;

        Assert.Throws<ArgumentNullException>(() => options!.WithCancellationToken(CancellationToken.None));
    }

    #endregion

    #region Extension Methods - Configure

    [Test]
    public void Configure_AppliesConfiguration()
    {
        var options = new CoseSign1ValidationOptions();

        var result = options.Configure(o =>
        {
            o.CertificateHeaderLocation = CoseHeaderLocation.Any;
        });

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.SameAs(options));
            Assert.That(options.CertificateHeaderLocation, Is.EqualTo(CoseHeaderLocation.Any));
        });
    }

    [Test]
    public void Configure_NullOptions_ThrowsArgumentNullException()
    {
        CoseSign1ValidationOptions? options = null;

        Assert.Throws<ArgumentNullException>(() => options!.Configure(_ => { }));
    }

    [Test]
    public void Configure_NullConfigure_ThrowsArgumentNullException()
    {
        var options = new CoseSign1ValidationOptions();

        Assert.Throws<ArgumentNullException>(() => options.Configure(null!));
    }

    #endregion

    #region Property Setters

    [Test]
    public void DetachedPayload_CanBeSetAndRetrieved()
    {
        var options = new CoseSign1ValidationOptions();
        var stream = new MemoryStream();

        options.DetachedPayload = stream;

        Assert.That(options.DetachedPayload, Is.SameAs(stream));
        stream.Dispose();
    }

    [Test]
    public void AssociatedData_CanBeSetAndRetrieved()
    {
        var options = new CoseSign1ValidationOptions();
        var data = new ReadOnlyMemory<byte>([1, 2, 3]);

        options.AssociatedData = data;

        Assert.That(options.AssociatedData, Is.EqualTo(data));
    }

    [Test]
    public void CertificateHeaderLocation_CanBeSetToAny()
    {
        var options = new CoseSign1ValidationOptions();

        options.CertificateHeaderLocation = CoseHeaderLocation.Any;

        Assert.That(options.CertificateHeaderLocation, Is.EqualTo(CoseHeaderLocation.Any));
    }

    #endregion
}
