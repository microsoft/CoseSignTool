// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests;

/// <summary>
/// Tests for <see cref="CoseKeyHeaderContributor"/>.
/// </summary>
[TestFixture]
public class CoseKeyHeaderContributorTests
{
    private const string TestKeyId = "https://test-vault.vault.azure.net/keys/test-key/abc123";
    private const int PS256Algorithm = -37;
    private const int ES256Algorithm = -7;

    #region Constructor Tests - RSA

    [Test]
    public void Constructor_WithRsaParams_SetsProperties()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        // Act
        var contributor = new CoseKeyHeaderContributor(rsaParams, PS256Algorithm, TestKeyId);

        // Assert
        Assert.That(contributor.KeyId, Is.EqualTo(TestKeyId));
        Assert.That(contributor.CoseAlgorithm, Is.EqualTo(PS256Algorithm));
        Assert.That(contributor.UseProtectedHeader, Is.False);
    }

    [Test]
    public void Constructor_WithRsaParams_WithoutKeyId_AllowsNullKeyId()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);

        // Act
        var contributor = new CoseKeyHeaderContributor(rsaParams, PS256Algorithm);

        // Assert
        Assert.That(contributor.KeyId, Is.Null);
    }

    [Test]
    public void Constructor_WithRsaPrivateParams_ThrowsArgumentException()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(true); // Include private key

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            new CoseKeyHeaderContributor(rsaParams, PS256Algorithm, TestKeyId));
    }

    [Test]
    public void Constructor_WithRsaNullModulus_ThrowsArgumentNullException()
    {
        // Arrange
        var rsaParams = new RSAParameters
        {
            Modulus = null,
            Exponent = new byte[] { 0x01, 0x00, 0x01 }
        };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CoseKeyHeaderContributor(rsaParams, PS256Algorithm, TestKeyId));
    }

    [Test]
    public void Constructor_WithRsaNullExponent_ThrowsArgumentNullException()
    {
        // Arrange
        var rsaParams = new RSAParameters
        {
            Modulus = new byte[256],
            Exponent = null
        };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CoseKeyHeaderContributor(rsaParams, PS256Algorithm, TestKeyId));
    }

    #endregion

    #region Constructor Tests - EC

    [Test]
    public void Constructor_WithEcParams_SetsProperties()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);

        // Act
        var contributor = new CoseKeyHeaderContributor(ecParams, ES256Algorithm, TestKeyId);

        // Assert
        Assert.That(contributor.KeyId, Is.EqualTo(TestKeyId));
        Assert.That(contributor.CoseAlgorithm, Is.EqualTo(ES256Algorithm));
    }

    [Test]
    public void Constructor_WithEcPrivateParams_ThrowsArgumentException()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(true); // Include private key

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            new CoseKeyHeaderContributor(ecParams, ES256Algorithm, TestKeyId));
    }

    [Test]
    public void Constructor_WithEcNullX_ThrowsArgumentNullException()
    {
        // Arrange
        var ecParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = null, Y = new byte[32] }
        };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CoseKeyHeaderContributor(ecParams, ES256Algorithm, TestKeyId));
    }

    [Test]
    public void Constructor_WithEcNullY_ThrowsArgumentNullException()
    {
        // Arrange
        var ecParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = new byte[32], Y = null }
        };

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            new CoseKeyHeaderContributor(ecParams, ES256Algorithm, TestKeyId));
    }

    #endregion

    #region MergeStrategy Tests

    [Test]
    public void MergeStrategy_ReturnsReplace()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(rsaParams, PS256Algorithm);

        // Act & Assert
        Assert.That(contributor.MergeStrategy, Is.EqualTo(HeaderMergeStrategy.Replace));
    }

    #endregion

    #region ContributeUnprotectedHeaders Tests (Default Behavior)

    [Test]
    public void ContributeUnprotectedHeaders_ByDefault_AddsCoseKeyHeader()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(rsaParams, PS256Algorithm, TestKeyId);
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(CoseKeyHeaderContributor.CoseKeyHeaderLabel), Is.True);
    }

    [Test]
    public void ContributeUnprotectedHeaders_ExistingHeader_ReplacesValue()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(rsaParams, PS256Algorithm, TestKeyId);
        var headers = new CoseHeaderMap();
        headers.Add(CoseKeyHeaderContributor.CoseKeyHeaderLabel, CoseHeaderValue.FromBytes(new byte[] { 0x00 }));
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert - Header is replaced with new COSE_Key
        Assert.That(headers.ContainsKey(CoseKeyHeaderContributor.CoseKeyHeaderLabel), Is.True);
        var headerValue = headers[CoseKeyHeaderContributor.CoseKeyHeaderLabel];
        var encodedValue = headerValue.EncodedValue.ToArray();
        Assert.That(encodedValue.Length, Is.GreaterThan(1)); // Should be real COSE_Key data
    }

    #endregion

    #region ContributeProtectedHeaders Tests

    [Test]
    public void ContributeProtectedHeaders_WhenUseProtectedHeaderFalse_DoesNotAdd()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(rsaParams, PS256Algorithm, TestKeyId);
        contributor.UseProtectedHeader = false;
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(CoseKeyHeaderContributor.CoseKeyHeaderLabel), Is.False);
    }

    [Test]
    public void ContributeProtectedHeaders_WhenUseProtectedHeaderTrue_AddsCoseKeyHeader()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(rsaParams, PS256Algorithm, TestKeyId);
        contributor.UseProtectedHeader = true;
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeProtectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(CoseKeyHeaderContributor.CoseKeyHeaderLabel), Is.True);
    }

    #endregion

    #region COSE_Key Encoding Tests - RSA

    [Test]
    public void RsaCoseKey_ContainsCorrectKeyType()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(rsaParams, PS256Algorithm, TestKeyId);
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert - Decode and verify COSE_Key structure
        var encodedValue = headers[CoseKeyHeaderContributor.CoseKeyHeaderLabel].EncodedValue.ToArray();
        var reader = new CborReader(encodedValue);
        var mapLength = reader.ReadStartMap();

        // Find kty (label 1)
        bool foundKty = false;
        for (int i = 0; i < mapLength; i++)
        {
            var label = reader.ReadInt32();
            if (label == CoseKeyHeaderContributor.CoseKeyLabels.KeyType)
            {
                var kty = reader.ReadInt32();
                Assert.That(kty, Is.EqualTo(CoseKeyHeaderContributor.CoseKeyTypes.RSA)); // RSA = 3
                foundKty = true;
                break;
            }
            reader.SkipValue();
        }

        Assert.That(foundKty, Is.True, "COSE_Key should contain kty (KeyType) label");
    }

    [Test]
    public void RsaCoseKey_ContainsModulusAndExponent()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(rsaParams, PS256Algorithm);
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert - Verify we can decode the COSE_Key (n and e are present)
        var encodedValue = headers[CoseKeyHeaderContributor.CoseKeyHeaderLabel].EncodedValue.ToArray();
        var reader = new CborReader(encodedValue);
        var mapLength = reader.ReadStartMap();

        bool foundN = false;
        bool foundE = false;

        for (int i = 0; i < mapLength; i++)
        {
            var label = reader.ReadInt32();
            if (label == CoseKeyHeaderContributor.RSALabels.N) // n = -1
            {
                var n = reader.ReadByteString();
                Assert.That(n, Is.EqualTo(rsaParams.Modulus));
                foundN = true;
            }
            else if (label == CoseKeyHeaderContributor.RSALabels.E) // e = -2
            {
                var e = reader.ReadByteString();
                Assert.That(e, Is.EqualTo(rsaParams.Exponent));
                foundE = true;
            }
            else
            {
                reader.SkipValue();
            }
        }

        Assert.That(foundN, Is.True, "COSE_Key should contain n (Modulus)");
        Assert.That(foundE, Is.True, "COSE_Key should contain e (Exponent)");
    }

    #endregion

    #region COSE_Key Encoding Tests - EC

    [Test]
    public void EcCoseKey_ContainsCorrectKeyType()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(ecParams, ES256Algorithm, TestKeyId);
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert - Decode and verify key type
        var encodedValue = headers[CoseKeyHeaderContributor.CoseKeyHeaderLabel].EncodedValue.ToArray();
        var reader = new CborReader(encodedValue);
        var mapLength = reader.ReadStartMap();

        bool foundKty = false;
        for (int i = 0; i < mapLength; i++)
        {
            var label = reader.ReadInt32();
            if (label == CoseKeyHeaderContributor.CoseKeyLabels.KeyType)
            {
                var kty = reader.ReadInt32();
                Assert.That(kty, Is.EqualTo(CoseKeyHeaderContributor.CoseKeyTypes.EC2)); // EC2 = 2
                foundKty = true;
                break;
            }
            reader.SkipValue();
        }

        Assert.That(foundKty, Is.True, "COSE_Key should contain kty (KeyType) label");
    }

    [Test]
    public void EcCoseKey_ContainsCurveAndCoordinates()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecParams = ecdsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(ecParams, ES256Algorithm);
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert
        var encodedValue = headers[CoseKeyHeaderContributor.CoseKeyHeaderLabel].EncodedValue.ToArray();
        var reader = new CborReader(encodedValue);
        var mapLength = reader.ReadStartMap();

        bool foundCrv = false;
        bool foundX = false;
        bool foundY = false;

        for (int i = 0; i < mapLength; i++)
        {
            var label = reader.ReadInt32();
            if (label == CoseKeyHeaderContributor.EC2Labels.Curve) // crv = -1
            {
                var crv = reader.ReadInt32();
                Assert.That(crv, Is.EqualTo(CoseKeyHeaderContributor.CoseEllipticCurves.P256));
                foundCrv = true;
            }
            else if (label == CoseKeyHeaderContributor.EC2Labels.X) // x = -2
            {
                var x = reader.ReadByteString();
                Assert.That(x, Is.EqualTo(ecParams.Q.X));
                foundX = true;
            }
            else if (label == CoseKeyHeaderContributor.EC2Labels.Y) // y = -3
            {
                var y = reader.ReadByteString();
                Assert.That(y, Is.EqualTo(ecParams.Q.Y));
                foundY = true;
            }
            else
            {
                reader.SkipValue();
            }
        }

        Assert.That(foundCrv, Is.True, "COSE_Key should contain crv (Curve)");
        Assert.That(foundX, Is.True, "COSE_Key should contain x coordinate");
        Assert.That(foundY, Is.True, "COSE_Key should contain y coordinate");
    }

    [Test]
    public void EcCoseKey_P384_HasCorrectCurveId()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ecParams = ecdsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(ecParams, -35); // ES384
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert - Find and verify curve ID
        var encodedValue = headers[CoseKeyHeaderContributor.CoseKeyHeaderLabel].EncodedValue.ToArray();
        var reader = new CborReader(encodedValue);
        var mapLength = reader.ReadStartMap();

        for (int i = 0; i < mapLength; i++)
        {
            var label = reader.ReadInt32();
            if (label == CoseKeyHeaderContributor.EC2Labels.Curve)
            {
                var crv = reader.ReadInt32();
                Assert.That(crv, Is.EqualTo(CoseKeyHeaderContributor.CoseEllipticCurves.P384));
                return;
            }
            reader.SkipValue();
        }

        Assert.Fail("Curve label not found");
    }

    [Test]
    public void EcCoseKey_P521_HasCorrectCurveId()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var ecParams = ecdsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(ecParams, -36); // ES512
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert - Find and verify curve ID
        var encodedValue = headers[CoseKeyHeaderContributor.CoseKeyHeaderLabel].EncodedValue.ToArray();
        var reader = new CborReader(encodedValue);
        var mapLength = reader.ReadStartMap();

        for (int i = 0; i < mapLength; i++)
        {
            var label = reader.ReadInt32();
            if (label == CoseKeyHeaderContributor.EC2Labels.Curve)
            {
                var crv = reader.ReadInt32();
                Assert.That(crv, Is.EqualTo(CoseKeyHeaderContributor.CoseEllipticCurves.P521));
                return;
            }
            reader.SkipValue();
        }

        Assert.Fail("Curve label not found");
    }

    #endregion

    #region Header Label Tests

    [Test]
    public void CoseKeyHeaderLabel_IsPrivateUseLabel()
    {
        // Per RFC 9052, private-use labels are negative integers
        // The label -65537 is below the range -65536 to -1
        Assert.That(CoseKeyHeaderContributor.CoseKeyHeaderLabel, Is.EqualTo(new CoseHeaderLabel(-65537)));
    }

    #endregion

    #region UseProtectedHeader Tests

    [Test]
    public void UseProtectedHeader_DefaultIsFalse()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(rsaParams, PS256Algorithm);

        // Assert
        Assert.That(contributor.UseProtectedHeader, Is.False);
    }

    [Test]
    public void UseProtectedHeader_CanBeSetToTrue()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(rsaParams, PS256Algorithm);

        // Act
        contributor.UseProtectedHeader = true;

        // Assert
        Assert.That(contributor.UseProtectedHeader, Is.True);
    }

    [Test]
    public void ContributeUnprotectedHeaders_WhenUseProtectedHeaderTrue_DoesNotAdd()
    {
        // Arrange
        using var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var contributor = new CoseKeyHeaderContributor(rsaParams, PS256Algorithm);
        contributor.UseProtectedHeader = true;
        var headers = new CoseHeaderMap();
        var context = CreateHeaderContributorContext();

        // Act
        contributor.ContributeUnprotectedHeaders(headers, context);

        // Assert
        Assert.That(headers.ContainsKey(CoseKeyHeaderContributor.CoseKeyHeaderLabel), Is.False);
    }

    #endregion

    #region Helper Methods

    private static HeaderContributorContext CreateHeaderContributorContext()
    {
        var payload = new byte[] { 0x01, 0x02, 0x03 };
        var signingContext = new SigningContext(payload, "application/octet-stream");
        var mockSigningKey = new Mock<ISigningKey>();
        return new HeaderContributorContext(signingContext, mockSigningKey.Object);
    }

    #endregion
}
