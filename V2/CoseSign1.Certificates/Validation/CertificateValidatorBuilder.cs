// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Domain-specific builder for adding certificate-related validators (signature + certificate properties + chain).
/// Intended to provide a fluent experience via <c>Cose.Sign1Message().AddCertificateValidator(b =&gt; ...)</c>.
/// </summary>
public interface ICertificateValidatorBuilder
{
    /// <summary>
    /// Configures whether to allow unprotected headers when looking up certificate material.
    /// This setting affects subsequent validator registrations on this builder.
    /// </summary>
    ICertificateValidatorBuilder AllowUnprotectedHeaders(bool allow = true);

    /// <summary>
    /// Adds a validator that verifies the message signature using X.509 certificate headers.
    /// For detached signatures, use the overload that supplies a payload.
    /// </summary>
    ICertificateValidatorBuilder ValidateSignature();

    /// <summary>
    /// Adds a validator that verifies a detached signature against the provided payload.
    /// </summary>
    ICertificateValidatorBuilder ValidateSignature(byte[] detachedPayload);

    /// <summary>
    /// Adds a validator that verifies a detached signature against the provided payload.
    /// </summary>
    ICertificateValidatorBuilder ValidateSignature(ReadOnlyMemory<byte> detachedPayload);

    /// <summary>
    /// Adds a validator that ensures the signing certificate is currently valid.
    /// </summary>
    ICertificateValidatorBuilder ValidateExpiration();

    /// <summary>
    /// Adds a validator that ensures the signing certificate is valid at the specified time.
    /// </summary>
    ICertificateValidatorBuilder ValidateExpiration(DateTime asOf);

    /// <summary>
    /// Adds a validator that enforces the signing certificate subject CN.
    /// </summary>
    ICertificateValidatorBuilder ValidateCommonName(string expectedCommonName);

    /// <summary>
    /// Adds a validator that enforces the signing certificate issuer CN.
    /// </summary>
    ICertificateValidatorBuilder ValidateIssuer(string expectedIssuerCommonName);

    /// <summary>
    /// Adds a validator that enforces a required key usage.
    /// </summary>
    ICertificateValidatorBuilder ValidateKeyUsage(X509KeyUsageFlags requiredKeyUsage);

    /// <summary>
    /// Adds a validator that enforces a required enhanced key usage (EKU).
    /// </summary>
    ICertificateValidatorBuilder ValidateEnhancedKeyUsage(Oid requiredEku);

    /// <summary>
    /// Adds a validator that enforces a required enhanced key usage (EKU) by OID string.
    /// </summary>
    ICertificateValidatorBuilder ValidateEnhancedKeyUsage(string requiredEkuOid);

    /// <summary>
    /// Adds a validator that validates the certificate chain using system roots.
    /// </summary>
    ICertificateValidatorBuilder ValidateChain(
        bool allowUntrusted = false,
        X509RevocationMode revocationMode = X509RevocationMode.Online);

    /// <summary>
    /// Adds a validator that validates the certificate chain using custom roots.
    /// </summary>
    ICertificateValidatorBuilder ValidateChain(
        X509Certificate2Collection customRoots,
        bool trustUserRoots = true,
        X509RevocationMode revocationMode = X509RevocationMode.Online);

    /// <summary>
    /// Adds a validator that validates the certificate chain using a custom chain builder.
    /// </summary>
    ICertificateValidatorBuilder ValidateChain(
        ICertificateChainBuilder chainBuilder,
        bool allowUntrusted = false,
        X509Certificate2Collection? customRoots = null,
        bool trustUserRoots = true);
}

internal sealed class CertificateValidatorBuilder : ICertificateValidatorBuilder
{
    private readonly List<IValidator<CoseSign1Message>> Validators = new();
    private bool AllowUnprotectedHeadersField;

    public ICertificateValidatorBuilder AllowUnprotectedHeaders(bool allow = true)
    {
        AllowUnprotectedHeadersField = allow;
        return this;
    }

    public ICertificateValidatorBuilder ValidateSignature()
    {
        Validators.Add(new CertificateSignatureValidator(AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidatorBuilder ValidateSignature(byte[] detachedPayload)
    {
        if (detachedPayload == null)
        {
            throw new ArgumentNullException(nameof(detachedPayload));
        }

        Validators.Add(new CertificateDetachedSignatureValidator(detachedPayload, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidatorBuilder ValidateSignature(ReadOnlyMemory<byte> detachedPayload)
    {
        Validators.Add(new CertificateDetachedSignatureValidator(detachedPayload, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidatorBuilder ValidateExpiration()
    {
        Validators.Add(new CertificateExpirationValidator(AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidatorBuilder ValidateExpiration(DateTime asOf)
    {
        Validators.Add(new CertificateExpirationValidator(asOf, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidatorBuilder ValidateCommonName(string expectedCommonName)
    {
        Validators.Add(new CertificateCommonNameValidator(expectedCommonName, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidatorBuilder ValidateIssuer(string expectedIssuerCommonName)
    {
        Validators.Add(new CertificateIssuerValidator(expectedIssuerCommonName, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidatorBuilder ValidateKeyUsage(X509KeyUsageFlags requiredKeyUsage)
    {
        Validators.Add(new CertificateKeyUsageValidator(requiredKeyUsage, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidatorBuilder ValidateEnhancedKeyUsage(Oid requiredEku)
    {
        Validators.Add(new CertificateKeyUsageValidator(requiredEku, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidatorBuilder ValidateEnhancedKeyUsage(string requiredEkuOid)
    {
        Validators.Add(new CertificateKeyUsageValidator(requiredEkuOid, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidatorBuilder ValidateChain(
        bool allowUntrusted = false,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        Validators.Add(new CertificateChainValidator(AllowUnprotectedHeadersField, allowUntrusted, revocationMode));
        return this;
    }

    public ICertificateValidatorBuilder ValidateChain(
        X509Certificate2Collection customRoots,
        bool trustUserRoots = true,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        if (customRoots == null)
        {
            throw new ArgumentNullException(nameof(customRoots));
        }

        Validators.Add(new CertificateChainValidator(customRoots, AllowUnprotectedHeadersField, trustUserRoots, revocationMode));
        return this;
    }

    public ICertificateValidatorBuilder ValidateChain(
        ICertificateChainBuilder chainBuilder,
        bool allowUntrusted = false,
        X509Certificate2Collection? customRoots = null,
        bool trustUserRoots = true)
    {
        if (chainBuilder == null)
        {
            throw new ArgumentNullException(nameof(chainBuilder));
        }

        Validators.Add(new CertificateChainValidator(chainBuilder, AllowUnprotectedHeadersField, allowUntrusted, customRoots, trustUserRoots));
        return this;
    }

    internal IReadOnlyList<IValidator<CoseSign1Message>> BuildValidators()
    {
        if (Validators.Count == 0)
        {
            throw new InvalidOperationException("No certificate validators configured");
        }

        return Validators;
    }
}
