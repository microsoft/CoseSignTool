// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Tests.Validation;

using System.Formats.Cbor;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;

[TestFixture]
public sealed class CertificateKeyMaterialResolutionValidatorTests
{
    private static readonly byte[] TestPayload = new byte[] { 1, 2, 3 };

    private static CoseSign1Message CreateMessageWithHeaders(CoseHeaderMap? protectedHeaders = null, CoseHeaderMap? unprotectedHeaders = null)
    {
        protectedHeaders ??= new CoseHeaderMap();
        using var key = ECDsa.Create();
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256, protectedHeaders, unprotectedHeaders);
        byte[] signedBytes = CoseSign1Message.SignDetached(TestPayload, signer, ReadOnlySpan<byte>.Empty);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    private static CoseHeaderValue CreateX5THeaderValue(X509Certificate2 cert)
    {
        var thumbprint = new CoseX509Thumbprint(cert, HashAlgorithmName.SHA256);
        var writer = new CborWriter();
        thumbprint.Serialize(writer);
        return CoseHeaderValue.FromEncodedValue(writer.Encode());
    }

    private static CoseHeaderValue CreateX5ChainHeaderValue(params X509Certificate2[] chain)
    {
        var writer = new CborWriter();

        if (chain.Length == 1)
        {
            writer.WriteByteString(chain[0].RawData);
        }
        else
        {
            writer.WriteStartArray(chain.Length);
            foreach (var cert in chain)
            {
                writer.WriteByteString(cert.RawData);
            }
            writer.WriteEndArray();
        }

        return CoseHeaderValue.FromEncodedValue(writer.Encode());
    }

    [Test]
    public void Stage_IsKeyMaterialResolution()
    {
        var validator = new CertificateKeyMaterialResolutionValidator();
        Assert.That(validator.Stages, Does.Contain(ValidationStage.KeyMaterialResolution));
    }

    [Test]
    public void IsApplicable_NullInput_ReturnsFalse()
    {
        var validator = new CertificateKeyMaterialResolutionValidator();
        Assert.That(validator.IsApplicable(null!, ValidationStage.KeyMaterialResolution), Is.False);
    }

    [Test]
    public void IsApplicable_NoCertificateHeaders_ReturnsFalse()
    {
        var validator = new CertificateKeyMaterialResolutionValidator();
        var message = CreateMessageWithHeaders();

        Assert.That(validator.IsApplicable(message, ValidationStage.KeyMaterialResolution), Is.False);
    }

    [Test]
    public void Validate_NullInput_FailsWithNullInputCode()
    {
        var validator = new CertificateKeyMaterialResolutionValidator();

        var result = validator.Validate(null!, ValidationStage.KeyMaterialResolution);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateKeyMaterialResolutionValidator)));
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo(CertificateKeyMaterialResolutionValidator.ClassStrings.ErrorCodeNullInput));
    }

    [Test]
    public void Validate_MissingChain_FailsWithX5ChainInvalid()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var protectedHeaders = new CoseHeaderMap
        {
            [CertificateHeaderContributor.HeaderLabels.X5T] = CreateX5THeaderValue(cert)
        };
        var message = CreateMessageWithHeaders(protectedHeaders);

        var validator = new CertificateKeyMaterialResolutionValidator();
        var result = validator.Validate(message, ValidationStage.KeyMaterialResolution);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo(CertificateKeyMaterialResolutionValidator.ClassStrings.ErrorCodeMissingOrInvalidChain));
    }

    [Test]
    public void Validate_MissingThumbprint_FailsWithX5TInvalid()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        var protectedHeaders = new CoseHeaderMap
        {
            [CertificateHeaderContributor.HeaderLabels.X5Chain] = CreateX5ChainHeaderValue(cert)
        };
        var message = CreateMessageWithHeaders(protectedHeaders);

        var validator = new CertificateKeyMaterialResolutionValidator();
        var result = validator.Validate(message, ValidationStage.KeyMaterialResolution);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo(CertificateKeyMaterialResolutionValidator.ClassStrings.ErrorCodeMissingOrInvalidThumbprint));
    }

    [Test]
    public void Validate_NoMatchingSigningCertInChain_FailsWithSigningCertNotFound()
    {
        using var cert = TestCertificateUtils.CreateCertificate();
        using var otherCert = TestCertificateUtils.CreateCertificate();

        var protectedHeaders = new CoseHeaderMap
        {
            [CertificateHeaderContributor.HeaderLabels.X5T] = CreateX5THeaderValue(cert),
            [CertificateHeaderContributor.HeaderLabels.X5Chain] = CreateX5ChainHeaderValue(otherCert)
        };
        var message = CreateMessageWithHeaders(protectedHeaders);

        var validator = new CertificateKeyMaterialResolutionValidator();
        var result = validator.Validate(message, ValidationStage.KeyMaterialResolution);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures, Has.Count.EqualTo(1));
        Assert.That(result.Failures[0].ErrorCode, Is.EqualTo(CertificateKeyMaterialResolutionValidator.ClassStrings.ErrorCodeSigningCertNotFound));
    }

    [Test]
    public void Validate_ValidThumbprintAndChain_SucceedsAndReturnsMetadata()
    {
        using var cert = TestCertificateUtils.CreateCertificate();

        var protectedHeaders = new CoseHeaderMap
        {
            [CertificateHeaderContributor.HeaderLabels.X5T] = CreateX5THeaderValue(cert),
            [CertificateHeaderContributor.HeaderLabels.X5Chain] = CreateX5ChainHeaderValue(cert)
        };
        var message = CreateMessageWithHeaders(protectedHeaders);

        var validator = new CertificateKeyMaterialResolutionValidator();
        var result = validator.Validate(message, ValidationStage.KeyMaterialResolution);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.ValidatorName, Is.EqualTo(nameof(CertificateKeyMaterialResolutionValidator)));
        Assert.That(result.Metadata, Is.Not.Null);
        Assert.That(result.Metadata!, Does.ContainKey(CertificateKeyMaterialResolutionValidator.ClassStrings.MetaKeyChainLength));
        Assert.That(result.Metadata!, Does.ContainKey(CertificateKeyMaterialResolutionValidator.ClassStrings.MetaKeySigningThumbprint));
        Assert.That(result.Metadata!, Does.ContainKey(CertificateKeyMaterialResolutionValidator.ClassStrings.MetaKeySigningSubject));
        Assert.That(result.Metadata![CertificateKeyMaterialResolutionValidator.ClassStrings.MetaKeyChainLength], Is.EqualTo(1));
    }

    [Test]
    public void Validate_AllowsUnprotectedHeaders_WhenEnabled()
    {
        using var cert = TestCertificateUtils.CreateCertificate();

        var unprotectedHeaders = new CoseHeaderMap
        {
            [CertificateHeaderContributor.HeaderLabels.X5T] = CreateX5THeaderValue(cert),
            [CertificateHeaderContributor.HeaderLabels.X5Chain] = CreateX5ChainHeaderValue(cert)
        };
        var message = CreateMessageWithHeaders(protectedHeaders: new CoseHeaderMap(), unprotectedHeaders);

        var validator = new CertificateKeyMaterialResolutionValidator(allowUnprotectedHeaders: true);
        Assert.That(validator.IsApplicable(message, ValidationStage.KeyMaterialResolution), Is.True);

        var result = validator.Validate(message, ValidationStage.KeyMaterialResolution);
        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public void ValidateAsync_CancellationRequested_ThrowsOperationCanceledException()
    {
        var validator = new CertificateKeyMaterialResolutionValidator();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.ThrowsAsync<OperationCanceledException>(async () =>
            await validator.ValidateAsync(CreateMessageWithHeaders(), ValidationStage.KeyMaterialResolution, cts.Token));
    }
}
