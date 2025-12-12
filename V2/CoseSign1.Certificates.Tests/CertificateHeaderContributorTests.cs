// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Tests.Common;
using NUnit.Framework;

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// Tests for CertificateHeaderContributor class.
/// Tests X5T and X5Chain header contribution for certificate-based signing.
/// </summary>
[TestFixture]
public class CertificateHeaderContributorTests
{
    [Test]
    public void ContributeProtectedHeaders_WithValidCertificate_AddsX5TAndX5Chain()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();
        var headers = new CoseHeaderMap();
        var testChain = TestCertificateUtils.CreateTestChain();
        var signingCert = testChain[0];
        var mockKey = new MockCertificateSigningKey(signingCert, testChain);
        var signingContext = new SigningContext(new MemoryStream(), "application/octet-stream");
        var context = new HeaderContributorContext(signingContext, mockKey);

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(2));
        Assert.That(headers.ContainsKey(CertificateHeaderContributor.HeaderLabels.X5T), Is.True);
        Assert.That(headers.ContainsKey(CertificateHeaderContributor.HeaderLabels.X5Chain), Is.True);
    }

    [Test]
    public void ContributeProtectedHeaders_WithNullHeaders_ThrowsArgumentNullException()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();
        var testChain = TestCertificateUtils.CreateTestChain();
        var mockKey = new MockCertificateSigningKey(testChain[0], testChain);
        var signingContext = new SigningContext(new MemoryStream(), "application/octet-stream");
        var context = new HeaderContributorContext(signingContext, mockKey);

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            contributor.ContributeProtectedHeaders(null!, context));
        Assert.That(ex.ParamName, Is.EqualTo("headers"));
    }

    [Test]
    public void ContributeProtectedHeaders_WithNullContext_ThrowsArgumentNullException()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();
        var headers = new CoseHeaderMap();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            contributor.ContributeProtectedHeaders(headers, null!));
        Assert.That(ex.ParamName, Is.EqualTo("context"));
    }

    [Test]
    public void ContributeProtectedHeaders_WithNonCertificateKey_DoesNotAddHeaders()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();
        var headers = new CoseHeaderMap();
        var mockNonCertKey = new MockNonCertificateSigningKey();
        var signingContext = new SigningContext(new MemoryStream(), "application/octet-stream");
        var context = new HeaderContributorContext(signingContext, mockNonCertKey);

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(0));
    }

    [Test]
    public void ContributeProtectedHeaders_WithNullSigningCertificate_ThrowsInvalidOperationException()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();
        var headers = new CoseHeaderMap();
        var testChain = TestCertificateUtils.CreateTestChain();
        var mockKey = new MockCertificateSigningKey(null, testChain); // Null signing cert
        var signingContext = new SigningContext(new MemoryStream(), "application/octet-stream");
        var context = new HeaderContributorContext(signingContext, mockKey);

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            contributor.ContributeProtectedHeaders(headers, context));
        Assert.That(ex.Message, Does.Contain("Signing certificate is not provided"));
    }

    [Test]
    public void ContributeProtectedHeaders_WithMismatchedChainCertificate_ThrowsInvalidOperationException()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();
        var headers = new CoseHeaderMap();
        var testChain = TestCertificateUtils.CreateTestChain();
        var signingCert = testChain[0];
        var mismatchedChain = new[] { testChain[1], testChain[2] }; // Chain doesn't start with signing cert
        var mockKey = new MockCertificateSigningKey(signingCert, mismatchedChain);
        var signingContext = new SigningContext(new MemoryStream(), "application/octet-stream");
        var context = new HeaderContributorContext(signingContext, mockKey);

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            contributor.ContributeProtectedHeaders(headers, context));
        Assert.That(ex.Message, Does.Contain("signing certificate thumbprint"));
        Assert.That(ex.Message, Does.Contain("must match the first item"));
    }

    [Test]
    public void ContributeProtectedHeaders_WithEmptyChain_ThrowsInvalidOperationException()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();
        var headers = new CoseHeaderMap();
        var testChain = TestCertificateUtils.CreateTestChain();
        var signingCert = testChain[0];
        var emptyChain = Array.Empty<X509Certificate2>();
        var mockKey = new MockCertificateSigningKey(signingCert, emptyChain);
        var signingContext = new SigningContext(new MemoryStream(), "application/octet-stream");
        var context = new HeaderContributorContext(signingContext, mockKey);

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            contributor.ContributeProtectedHeaders(headers, context));
        Assert.That(ex.Message, Does.Contain("must match the first item"));
    }

    [Test]
    public void ContributeProtectedHeaders_X5THeader_ContainsValidThumbprint()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();
        var headers = new CoseHeaderMap();
        var testChain = TestCertificateUtils.CreateTestChain();
        var signingCert = testChain[0];
        var mockKey = new MockCertificateSigningKey(signingCert, testChain);
        var signingContext = new SigningContext(new MemoryStream(), "application/octet-stream");
        var context = new HeaderContributorContext(signingContext, mockKey);

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        var x5tHeader = headers[CertificateHeaderContributor.HeaderLabels.X5T];
        var encodedValue = x5tHeader.EncodedValue;
        Assert.That(encodedValue.Length, Is.GreaterThan(0));

        // Verify it can be deserialized as CBOR
        var reader = new CborReader(encodedValue);
        Assert.DoesNotThrow(() => reader.ReadStartArray());
    }

    [Test]
    public void ContributeProtectedHeaders_X5ChainHeader_ContainsValidChain()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();
        var headers = new CoseHeaderMap();
        var testChain = TestCertificateUtils.CreateTestChain();
        var signingCert = testChain[0];
        var mockKey = new MockCertificateSigningKey(signingCert, testChain);
        var signingContext = new SigningContext(new MemoryStream(), "application/octet-stream");
        var context = new HeaderContributorContext(signingContext, mockKey);

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        var x5chainHeader = headers[CertificateHeaderContributor.HeaderLabels.X5Chain];
        var encodedValue = x5chainHeader.EncodedValue;
        Assert.That(encodedValue.Length, Is.GreaterThan(0));

        // Verify it can be deserialized as CBOR array
        var reader = new CborReader(encodedValue);
        Assert.DoesNotThrow(() => reader.ReadStartArray());
    }

    [Test]
    public void ContributeUnprotectedHeaders_DoesNotAddHeaders()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();
        var headers = new CoseHeaderMap();
        var testChain = TestCertificateUtils.CreateTestChain();
        var mockKey = new MockCertificateSigningKey(testChain[0], testChain);
        var signingContext = new SigningContext(new MemoryStream(), "application/octet-stream");
        var context = new HeaderContributorContext(signingContext, mockKey);

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(0));
    }

    [Test]
    public void MergeStrategy_ReturnsFail()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();

        // Act
        var strategy = contributor.MergeStrategy;

        // Assert
        Assert.That(strategy, Is.EqualTo(HeaderMergeStrategy.Fail));
    }

    [Test]
    public void ContributeProtectedHeaders_WithSingleCertificateChain_AddsCorrectHeaders()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();
        var headers = new CoseHeaderMap();
        var testChain = TestCertificateUtils.CreateTestChain();
        var signingCert = testChain[0];
        var singleCertChain = new[] { signingCert }; // Only leaf cert
        var mockKey = new MockCertificateSigningKey(signingCert, singleCertChain);
        var signingContext = new SigningContext(new MemoryStream(), "application/octet-stream");
        var context = new HeaderContributorContext(signingContext, mockKey);

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(2));
        Assert.That(headers.ContainsKey(CertificateHeaderContributor.HeaderLabels.X5T), Is.True);
        Assert.That(headers.ContainsKey(CertificateHeaderContributor.HeaderLabels.X5Chain), Is.True);
    }

    [Test]
    public void ContributeProtectedHeaders_WithThreeCertificateChain_AddsCorrectHeaders()
    {
        // Arrange
        var contributor = new CertificateHeaderContributor();
        var headers = new CoseHeaderMap();
        var testChain = TestCertificateUtils.CreateTestChain();
        var signingCert = testChain[0];
        var mockKey = new MockCertificateSigningKey(signingCert, testChain);
        var signingContext = new SigningContext(new MemoryStream(), "application/octet-stream");
        var context = new HeaderContributorContext(signingContext, mockKey);

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.Count, Is.EqualTo(2));

        // Verify both headers are present and have valid CBOR data
        var x5t = headers[CertificateHeaderContributor.HeaderLabels.X5T];
        var x5chain = headers[CertificateHeaderContributor.HeaderLabels.X5Chain];
        Assert.That(x5t.EncodedValue.Length, Is.GreaterThan(0));
        Assert.That(x5chain.EncodedValue.Length, Is.GreaterThan(0));
    }

    #region Helper Classes

    /// <summary>
    /// Mock implementation of ICertificateSigningKey for testing.
    /// </summary>
    private class MockCertificateSigningKey : ICertificateSigningKey
    {
        private readonly X509Certificate2? SigningCert;
        private readonly IEnumerable<X509Certificate2> Chain;

        public MockCertificateSigningKey(X509Certificate2? signingCert, IEnumerable<X509Certificate2> chain)
        {
            SigningCert = signingCert;
            Chain = chain ?? Enumerable.Empty<X509Certificate2>();
        }

        public X509Certificate2 GetSigningCertificate() => SigningCert!;

        public IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder)
        {
            return sortOrder == X509ChainSortOrder.LeafFirst ? Chain : Chain.Reverse();
        }

        public CoseKey GetCoseKey() => throw new NotImplementedException();
        public SigningKeyMetadata Metadata => throw new NotImplementedException()!;
        public ISigningService<SigningOptions> SigningService => throw new NotImplementedException()!;
        public void Dispose() { }
    }

    /// <summary>
    /// Mock non-certificate signing key for testing the contributor skips non-certificate keys.
    /// </summary>
    private class MockNonCertificateSigningKey : ISigningKey
    {
        public CoseKey GetCoseKey() => throw new NotImplementedException();
        public SigningKeyMetadata Metadata => throw new NotImplementedException()!;
        public ISigningService<SigningOptions> SigningService => throw new NotImplementedException()!;
        public void Dispose() { }
    }

    #endregion
}