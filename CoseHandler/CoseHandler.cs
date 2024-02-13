// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseX509;

using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using CoseSign1;
using CoseSign1.Abstractions;
using CoseSign1.Abstractions.Interfaces;
using CoseSign1.Certificates.Exceptions;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Certificates.Local;
using CoseSign1.Certificates.Local.Validators;
using CoseSign1.Extensions;
using CoseSign1.Interfaces;
using CoseDetachedSignature.Extensions;

/// <summary>
/// Contains static methods to generate and validate Cose X509 signatures.
/// </summary>
public static class CoseHandler
{
    // Store name of the default certificate store
    private const string DefaultStoreName = "My";

    // static instance of the factory for creating new CoseSign1Messages
    private static readonly ICoseSign1MessageFactory Factory = new CoseSign1MessageFactory();

    #region Sign Overloads
    /// <summary>
    /// Signs the payload content with the supplied certificate and returns a ReadOnlyMemory object containing the COSE signatureFile.
    /// </summary>
    /// <param name="payload">The file content to sign.</param>
    /// <param name="certificate">The certificate to sign with.</param>
    /// <param name="embedSign">True to embed an encoded copy of the payload content into the COSE signature structure.
    /// By default, the COSE signature uses a hash match to compare to the original content. This is called "detached" signing.</param>
    /// <param name="signatureFile">.Optional. Writes the COSE signature to the specified file location.
    /// For file extension, we recommend ".cose" for detached signatures, or ".csm" if the file is embed-signed.</param>
    /// <param name="contentType"/>Optional. A MIME type value to set as the Content Type of the payload. Default value is "application/cose".</param>
    /// <exception cref="CoseSigningException">Unsupported certificate type for COSE signing, or the certificate chain could not be built.</exception>
    /// <exception cref="CryptographicException">The signing certificate is null or invalid.</exception>
    public static ReadOnlyMemory<byte> Sign(
        byte[] payload,
        X509Certificate2 certificate,
        bool embedSign = false,
        FileInfo? signatureFile = null,
        string? contentType = CoseSign1MessageFactory.DEFAULT_CONTENT_TYPE)
        => Sign(
            payload,
            signingKeyProvider: new X509Certificate2CoseSigningKeyProvider(null, certificate),
            embedSign, signatureFile, contentType);

    /// <summary>
    /// Signs the payload content with the supplied certificate and returns a ReadOnlyMemory object containing the COSE signatureFile.
    /// </summary>
    /// <param name="payload">A Stream containing the file content to sign.</param>
    /// <param name="certificate">The certificate to sign with.</param>
    /// <param name="embedSign">True to embed an encoded copy of the payload content into the COSE signature structure.
    /// By default, the COSE signature uses a hash match to compare to the original content. This is called "detached" signing.</param>
    /// <param name="signatureFile">.Optional. Writes the COSE signature to the specified file location.
    /// For file extension, we recommend ".cose" for detached signatures, or ".csm" if the file is embed-signed.</param>
    /// <param name="contentType"/>Optional. A MIME type value to set as the Content Type of the payload. Default value is "application/cose".</param>
    /// <exception cref="CoseSigningException">Unsupported certificate type for COSE signing, or the certificate chain could not be built.</exception>
    /// <exception cref="CryptographicException">The signing certificate is null or invalid.</exception>
    public static ReadOnlyMemory<byte> Sign(
        Stream payload,
        X509Certificate2 certificate,
        bool embedSign = false,
        FileInfo? signatureFile = null,
        string? contentType = CoseSign1MessageFactory.DEFAULT_CONTENT_TYPE)
        => Sign(
            payload,
            signingKeyProvider: new X509Certificate2CoseSigningKeyProvider(null, certificate),
            embedSign, signatureFile, contentType);

    /// <summary>
    /// Signs the payload content with the supplied certificate and returns a ReadOnlyMemory object containing the COSE signatureFile.
    /// </summary>
    /// <param name="payload">The file to sign.</param>
    /// <param name="certificate">The certificate to sign with.</param>
    /// <param name="embedSign">True to embed an encoded copy of the payload content into the COSE signature structure.
    /// By default, the COSE signature uses a hash match to compare to the original content. This is called "detached" signing.</param>
    /// <param name="signatureFile">.Optional. Writes the COSE signature to the specified file location.
    /// For file extension, we recommend ".cose" for detached signatures, or ".csm" if the file is embed-signed.</param>
    /// <param name="contentType"/>Optional. A MIME type value to set as the Content Type of the payload. Default value is "application/cose".</param>
    /// <exception cref="CoseSigningException">Unsupported certificate type for COSE signing, or the certificate chain could not be built.</exception>
    /// <exception cref="CryptographicException">The signing certificate is null or invalid.</exception>
    /// <exception cref="FileNotFoundException">The payload file could not be found.</exception>
    /// <exception cref="DirectoryNotFoundException">The parent directory of the payload file could not be found.</exception>
    /// <exception cref="PathTooLongException">The path to the payload file exceeded max path length.</exception>
    /// <exception cref="UnauthorizedAccessException">The current user is not authorized to read the payload file or open its parent directory.</exception>
    public static ReadOnlyMemory<byte> Sign(
        FileInfo payload,
        X509Certificate2 certificate,
        bool embedSign = false,
        FileInfo? signatureFile = null,
        string? contentType = CoseSign1MessageFactory.DEFAULT_CONTENT_TYPE)
        => Sign(
            payload,
            signingKeyProvider: new X509Certificate2CoseSigningKeyProvider(null, certificate),
            embedSign, signatureFile, contentType);

    /// <summary>
    /// Signs the payload content with the supplied certificate and returns a ReadOnlyMemory object containing the COSE signatureFile.
    /// </summary>
    /// <param name="payload">The file content to sign.</param>
    /// <param name="thumbprint">The SHA1 thumbprint of an installed certificate to sign with.</param>
    /// <param name="embedSign">True to embed an encoded copy of the payload content into the COSE signature structure.
    /// By default, the COSE signature uses a hash match to compare to the original content. This is called "detached" signing.</param>
    /// <param name="signatureFile">.Optional. Writes the COSE signature to the specified file location.
    /// For file extension, we recommend ".cose" for detached signatures, or ".csm" if the file is embed-signed.</param>
    /// <param name="storeName">Optional. The name of the certificate store that contains the signing certificate. Default is "My".</param>
    /// <param name="storeLocation">Optional. The location of the certificate store that contains the signing certificate. Default is "CurrentUser".</param>
    /// <param name="contentType"/>Optional. A MIME type value to set as the Content Type of the payload. Default value is "application/cose".</param>
    /// <exception cref="CoseSigningException">Unsupported certificate type for COSE signing, or the certificate chain could not be built.</exception>
    /// <exception cref="CryptographicException">The signing certificate is null or invalid.</exception>
    public static ReadOnlyMemory<byte> Sign(
        byte[] payload,
        string thumbprint,
        bool embedSign = false,
        FileInfo? signatureFile = null,
        string storeName = "My",
        StoreLocation storeLocation = StoreLocation.CurrentUser,
        string? contentType = CoseSign1MessageFactory.DEFAULT_CONTENT_TYPE)
        => Sign(
            payload,
            certificate: LookupCertificate(thumbprint, storeName, storeLocation),
            embedSign, signatureFile, contentType);

    /// <summary>
    /// Signs the payload content with the supplied certificate and returns a ReadOnlyMemory object containing the COSE signatureFile.
    /// </summary>
    /// <param name="payload">A Stream containing the file content to sign.</param>
    /// <param name="thumbprint">The SHA1 thumbprint of an installed certificate to sign with.</param>
    /// <param name="embedSign">True to embed an encoded copy of the payload content into the COSE signature structure.
    /// By default, the COSE signature uses a hash match to compare to the original content. This is called "detached" signing.</param>
    /// <param name="signatureFile">.Optional. Writes the COSE signature to the specified file location.
    /// For file extension, we recommend ".cose" for detached signatures, or ".csm" if the file is embed-signed.</param>
    /// <param name="storeName">Optional. The name of the certificate store that contains the signing certificate. Default is "My".</param>
    /// <param name="storeLocation">Optional. The location of the certificate store that contains the signing certificate. Default is "CurrentUser".</param>
    /// <param name="contentType"/>Optional. A MIME type value to set as the Content Type of the payload. Default value is "application/cose".</param>
    /// <exception cref="CoseSigningException">Unsupported certificate type for COSE signing, or the certificate chain could not be built.</exception>
    /// <exception cref="CryptographicException">The signing certificate is null or invalid.</exception>
    public static ReadOnlyMemory<byte> Sign(
        Stream payload,
        string thumbprint,
        bool embedSign = false,
        FileInfo? signatureFile = null,
        string storeName = "My",
        StoreLocation storeLocation = StoreLocation.CurrentUser,
        string? contentType = CoseSign1MessageFactory.DEFAULT_CONTENT_TYPE)
        => Sign(
            payload,
            certificate: LookupCertificate(thumbprint, storeName, storeLocation),
            embedSign, signatureFile, contentType);

    /// <summary>
    /// Signs the payload content with the supplied certificate and returns a ReadOnlyMemory object containing the COSE signatureFile.
    /// </summary>
    /// <param name="payload">The file to sign.</param>
    /// <param name="thumbprint">The SHA1 thumbprint of an installed certificate to sign with.</param>
    /// <param name="embedSign">True to embed an encoded copy of the payload content into the COSE signature structure.
    /// By default, the COSE signature uses a hash match to compare to the original content. This is called "detached" signing.</param>
    /// <param name="signatureFile">.Optional. Writes the COSE signature to the specified file location.
    /// For file extension, we recommend ".cose" for detached signatures, or ".csm" if the file is embed-signed.</param>
    /// <param name="storeName">Optional. The name of the certificate store that contains the signing certificate. Default is "My".</param>
    /// <param name="storeLocation">Optional. The location of the certificate store that contains the signing certificate. Default is "CurrentUser".</param>
    /// <exception cref="CoseSigningException">Unsupported certificate type for COSE signing, or the certificate chain could not be built.</exception>
    /// <exception cref="CryptographicException">The signing certificate is null or invalid.</exception>
    /// <exception cref="FileNotFoundException">The payload file could not be found.</exception>
    /// <exception cref="DirectoryNotFoundException">The parent directory of the payload file could not be found.</exception>
    /// <exception cref="PathTooLongException">The path to the payload file exceeded max path length.</exception>
    /// <exception cref="UnauthorizedAccessException">The current user is not authorized to read the payload file or open its parent directory.</exception>
    public static ReadOnlyMemory<byte> Sign(
        FileInfo payload,
        string thumbprint,
        bool embedSign = false,
        FileInfo? signatureFile = null,
        string storeName = "My",
        StoreLocation storeLocation = StoreLocation.CurrentUser,
        string? contentType = CoseSign1MessageFactory.DEFAULT_CONTENT_TYPE)
        => Sign(
            payload,
            certificate: LookupCertificate(thumbprint, storeName, storeLocation),
            embedSign, signatureFile, contentType);

    /// <summary>
    /// Signs the payload content with the supplied certificate and returns a ReadOnlyMemory object containing the COSE signatureFile.
    /// </summary>
    /// <param name="payload">The file content to sign.</param>
    /// <param name="signingKeyProvider">An CertificateCoseSigningKeyProvider that contains the signing certificate and hash information.</param>
    /// <param name="embedSign">True to embed an encoded copy of the payload content into the COSE signature structure.
    /// By default, the COSE signature uses a hash match to compare to the original content. This is called "detached" signing.</param>
    /// <param name="signatureFile">.Optional. Writes the COSE signature to the specified file location.
    /// For file extension, we recommend ".cose" for detached signatures, or ".csm" if the file is embed-signed.</param>
    /// <param name="contentType"/>Optional. A MIME type value to set as the Content Type of the payload. Default value is "application/cose".</param>
    /// <param name="headerExtender">Optional. Provides the ability to add custom Cose Headers <see cref="ICoseHeaderExtender"/></param>
    /// <exception cref="CoseSigningException">Unsupported certificate type for COSE signing, or the certificate chain could not be built.</exception>
    /// <exception cref="CryptographicException">The signing certificate is null or invalid.</exception>
    public static ReadOnlyMemory<byte> Sign(
        byte[] payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedSign = false,
        FileInfo? signatureFile = null,
        string? contentType = CoseSign1MessageFactory.DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null)
        => SignInternal(
            payloadBytes: payload,
            payloadStream: null,
            signingKeyProvider, embedSign, signatureFile, contentType, headerExtender);

    /// <summary>
    /// Signs the payload content with the supplied certificate and returns a ReadOnlyMemory object containing the COSE signatureFile.
    /// </summary>
    /// <param name="payload">A Stream containing the file content to sign.</param>
    /// <param name="signingKeyProvider">An CertificateCoseSigningKeyProvider that contains the signing certificate and hash information.</param>
    /// <param name="embedSign">True to embed an encoded copy of the payload content into the COSE signature structure.
    /// By default, the COSE signature uses a hash match to compare to the original content. This is called "detached" signing.</param>
    /// <param name="signatureFile">.Optional. Writes the COSE signature to the specified file location.
    /// For file extension, we recommend ".cose" for detached signatures, or ".csm" if the file is embed-signed.</param>
    /// <param name="contentType"/>Optional. A MIME type value to set as the Content Type of the payload. Default value is "application/cose".</param>
    /// <param name="headerExtender">Optional. Provides the ability to add custom Cose Headers <see cref="ICoseHeaderExtender"/></param>
    /// <exception cref="CoseSigningException">Unsupported certificate type for COSE signing, or the certificate chain could not be built.</exception>
    /// <exception cref="CryptographicException">The signing certificate is null or invalid.</exception>
    public static ReadOnlyMemory<byte> Sign(
        Stream payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedSign = false,
        FileInfo? signatureFile = null,
        string? contentType = CoseSign1MessageFactory.DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null)
        => SignInternal(
            payloadBytes: null,
            payloadStream: payload,
            signingKeyProvider, embedSign, signatureFile, contentType, headerExtender);

    /// <summary>
    /// Signs the payload content with the supplied certificate and returns a ReadOnlyMemory object containing the COSE signatureFile.
    /// </summary>
    /// <param name="payload">The file to sign.</param>
    /// <param name="signingKeyProvider">An CertificateCoseSigningKeyProvider that contains the signing certificate and hash information.</param>
    /// <param name="embedSign">True to embed an encoded copy of the payload content into the COSE signature structure.
    /// By default, the COSE signature uses a hash match to compare to the original content. This is called "detached" signing.</param>
    /// <param name="signatureFile">.Optional. Writes the COSE signature to the specified file location.
    /// For file extension, we recommend ".cose" for detached signatures, or ".csm" if the file is embed-signed.</param>
    /// <param name="headerExtender">Optional. Provides the ability to add custom Cose Headers <see cref="ICoseHeaderExtender"/></param>
    /// <exception cref="CryptographicException">The signing certificate is null or invalid.</exception>
    /// <exception cref="FileNotFoundException">The payload file could not be found.</exception>
    /// <exception cref="DirectoryNotFoundException">The parent directory of the payload file could not be found.</exception>
    /// <exception cref="PathTooLongException">The path to the payload file exceeded max path length.</exception>
    /// <exception cref="UnauthorizedAccessException">The current user is not authorized to read the payload file or open its parent directory.</exception>
    public static ReadOnlyMemory<byte> Sign(
        FileInfo payload,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedSign = false,
        FileInfo? signatureFile = null,
        string? contentType = CoseSign1MessageFactory.DEFAULT_CONTENT_TYPE,
        ICoseHeaderExtender? headerExtender = null)
        => SignInternal(
            payloadBytes: null,
            payloadStream: payload.OpenRead(),
            signingKeyProvider, embedSign, signatureFile, contentType, headerExtender);

    /// <summary>
    /// Signs a file with the supplied key provider.
    /// </summary>
    /// <param name="payload">The content to be signatureFile. This may be a byte[], a Stream, or a string. If string, it will be read as a file path.</param>
    /// <param name="signingKeyProvider">An CertificateCoseSigningKeyProvider that contains the signing certificate and hash information.</param>
    /// <param name="embedSign">True to embed an encoded copy of the payload content into the COSE signature structure.
    /// <param name="signatureFile">.Optional. Writes the COSE signature to the specified file location.
    /// For file extension, we recommend ".cose" for detached signatures, or ".csm" if the file is embed-signed.</param>
    /// <param name="headerExtender">Optional. Provides the ability to add custom Cose Headers <see cref="ICoseHeaderExtender"/></param>
    /// <returns>The COSE signature structure in a read-only byte array.</returns>
    internal static ReadOnlyMemory<byte> SignInternal(
        byte[]? payloadBytes,
        Stream? payloadStream,
        ICoseSigningKeyProvider signingKeyProvider,
        bool embedSign,
        FileInfo? signatureFile,
        string? contentType,
        ICoseHeaderExtender ? headerExtender = null)
    {
        // Sign the payload.
#pragma warning disable CS8604 // Possible null reference argument: False positive on contentType param which has a default value.
        ReadOnlyMemory<byte> signedBytes =
            !payloadBytes.IsNullOrEmpty() ?
                Factory.CreateCoseSign1MessageBytes(payloadBytes, signingKeyProvider, embedSign, contentType, headerExtender) :
            payloadStream is not null ?
                Factory.CreateCoseSign1MessageBytes(payloadStream, signingKeyProvider, embedSign, contentType, headerExtender) :
                throw new ArgumentException("Payload not provided.");
#pragma warning restore CS8604 // Possible null reference argument.

        // Write to file if requested.
        if (signatureFile is not null)
        {
            // Use the static method here because signatureFile.OpenWrite().Write() was sometimes truncating the last byte from signedBytes.
            File.WriteAllBytes(signatureFile.FullName, signedBytes.ToArray());
        }

        return signedBytes;
    }
#endregion

    #region Validate Overloads
    /// <summary>
    /// Validates a detached or embedded COSE signature in memory.
    /// </summary>
    /// <param name="signature">A byte array containing the COSE signatureFile.</param>
    /// <param name="payload">Detached signatures only: A byte array containing the original payload. Leave as <code>null</code> for embedded signatures.</param>
    /// <param name="roots">Optional. A set of root certificates to try to chain the signing certificate to, in addition to the certificates installed on the host machine.</param>
    /// <param name="revocationMode">Optional. Revocation mode to use when validating the certificate chain.</param>
    /// <param name="requiredCommonName">Optional. Requires the signing certificate to match the specified Common Name.</param>
    /// <exception cref="CoseValidationException">The exception thrown if validation failed</exception>
    public static ValidationResult Validate(
        byte[] signature,
        byte[]? payload,
        List<X509Certificate2>? roots = null,
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        string? requiredCommonName = null,
        bool allowUntrusted = false)
        => Validate(signature, GetValidator(roots, revocationMode, requiredCommonName, allowUntrusted), payload);

    /// <summary>
    /// Validates a detached COSE signature in memory.
    /// </summary>
    /// <param name="signature">A byte array containing the COSE signatureFile.</param>
    /// <param name="payload">Detached signatures only: A stream of the source file containing the original payload.</param>
    /// <param name="roots">Optional. A set of root certificates to try to chain the signing certificate to, in addition to the certificates installed on the host machine.</param>
    /// <param name="revocationMode">Optional. Revocation mode to use when validating the certificate chain.</param>
    /// <param name="requiredCommonName">Optional. Requires the signing certificate to match the specified Common Name.</param>
    public static ValidationResult Validate(
        byte[] signature,
        Stream payload,
        List<X509Certificate2>? roots = null,
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        string? requiredCommonName = null,
        bool allowUntrusted = false)
        => Validate(signature, GetValidator(roots, revocationMode, requiredCommonName, allowUntrusted), payload);

    /// <summary>
    /// Validates a detached or embedded COSE signature in memory.
    /// </summary>
    /// <param name="signature">The COSE signature file to validate.</param>
    /// <param name="payload">Detached signatures only: A byte array containing the original payload. Leave as <code>null</code> for embedded signatures.</param>
    /// <param name="roots">Optional. A set of root certificates to try to chain the signing certificate to, in addition to the certificates installed on the host machine.</param>
    /// <param name="revocationMode">Optional. Revocation mode to use when validating the certificate chain.</param>
    /// <param name="requiredCommonName">Optional. Requires the signing certificate to match the specified Common Name.</param>
    public static ValidationResult Validate(
        Stream signature,
        byte[]? payload,
        List<X509Certificate2>? roots = null,
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        string? requiredCommonName = null,
        bool allowUntrusted = false)
        => Validate(signature, GetValidator(roots, revocationMode, requiredCommonName, allowUntrusted), payload);

    /// <summary>
    /// Validates a COSE signature file.
    /// </summary>
    /// <param name="signature">The COSE signatureFile to validate.</param>
    /// <param name="payload">Detached signatures only: The original payload file. Leave as <code>null</code> for embedded signatures.</param>
    /// <param name="roots">Optional. A set of root certificates to try to chain the signing certificate to, in addition to the certificates installed on the host machine.</param>
    /// <param name="revocationMode">Optional. Revocation mode to use when validating the certificate chain.</param>
    /// <param name="requiredCommonName">Optional. Requires the signing certificate to match the specified Common Name.</param>
    public static ValidationResult Validate(
        FileInfo signature,
        FileInfo? payload,
        List<X509Certificate2>? roots = null,
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        string? requiredCommonName = null,
        bool allowUntrusted = false)
        => Validate(
            File.ReadAllBytes(signature.FullName),
            GetValidator(roots, revocationMode, requiredCommonName, allowUntrusted),
            payload?.OpenRead());

    /// <summary>
    /// Validates a detached COSE signature in memory.
    /// </summary>
    /// <param name="signature">A byte array containing the COSE signatureFile.</param>
    /// <param name="payload">Detached signatures only: A Stream containing the original payload. Leave as <code>null</code> for embedded signatures.</param>
    /// <param name="roots">Optional. A set of root certificates to try to chain the signing certificate to, in addition to the certificates installed on the host machine.</param>
    /// <param name="revocationMode">Optional. Revocation mode to use when validating the certificate chain.</param>
    /// <param name="requiredCommonName">Optional. Requires the signing certificate to match the specified Common Name.</param>
    public static ValidationResult Validate(
        Stream signature,
        Stream? payload,
        List<X509Certificate2>? roots = null,
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        string? requiredCommonName = null,
        bool allowUntrusted = false)
        => Validate(signature, GetValidator(roots, revocationMode, requiredCommonName, allowUntrusted), payload);

    /// <summary>
    /// Validates a detached or embedded COSE signature in  memory.
    /// </summary>
    /// <param name="signature">A byte array containing the COSE signatureFile.</param>
    /// <param name="validator">A <see cref="CoseSign1MessageValidator"/> to validate the signature with, or <see cref="CoseSign1MessageValidator.None"/> to only check certificate validity and payload integrity.</param>
    /// <param name="payload">For detached signatures, a byte array or Stream object containing the original payload; null for embedded signatures.</param>
    /// <exception cref="CoseValidationException">Validation failed</exception>
    /// <remarks>An <see cref="X509ChainTrustValidator"/> is recommended to ensure that the signing certificate chains to a valid root. You can also add an <see cref="X509CommonNameValidator"/> as a <see cref="CoseSign1MessageValidator.NextElement"/> to require a specific certificate Common Name.</remarks>
    public static ValidationResult Validate(
        byte[] signature,
        CoseSign1MessageValidator validator,
        byte[]? payload = null)
        => ValidateInternal(signature, payload, payloadStream: null, content: out _, validator);

    /// <summary>
    /// Validates a detached or embedded COSE signature in memory.
    /// </summary>
    /// <param name="signature">The COSE signature stream to validate.</param>
    /// <param name="validator">A <see cref="CoseSign1MessageValidator"/> to validate the signature structure with, or <see cref="CoseSign1MessageValidator.None"/> to only check certificate validity and payload integrity.</param>
    /// <param name="payload">For detached signatures, a string pointing to the original file that was signed, or a byte array or Stream object containing the original payload; null for embedded signatures.</param>
    /// <exception cref="CoseValidationException">Validation failed</exception>
    /// <remarks>An <see cref="X509ChainTrustValidator"/> is recommended to ensure that the signing certificate chains to a valid root. You can also add an <see cref="X509CommonNameValidator"/> as a <see cref="CoseSign1MessageValidator.NextElement"/> to require a specific certificate Common Name.</remarks>
    public static ValidationResult Validate(
        Stream signature,
        CoseSign1MessageValidator validator,
        byte[]? payload = null)
        => ValidateInternal(signature.GetBytes(), payload, payloadStream: null, out _, validator);

    /// <summary>
    /// Validates a detached or embedded COSE signature in memory.
    /// </summary>
    /// <param name="signature">A byte array containing the COSE signature file.</param>
    /// <param name="validator">A <see cref="CoseSign1MessageValidator"/> to validate the signature with, or <see cref="CoseSign1MessageValidator.None"/> to only check certificate validity and payload integrity.</param>
    /// <param name="payload">For detached signatures, the original payload that was signed; null for embedded signatures.</param>
    /// <exception cref="CoseValidationException">Validation failed</exception>
    /// <remarks>An <see cref="X509ChainTrustValidator"/> is recommended to ensure that the signing certificate chains to a valid root. You can also add an <see cref="X509CommonNameValidator"/> as a <see cref="CoseSign1MessageValidator.NextElement"/> to require a specific certificate Common Name.</remarks>
    public static ValidationResult Validate(
        byte[] signature,
        CoseSign1MessageValidator validator,
        Stream? payload)
        => ValidateInternal(signature, payloadBytes: null, payload, content: out _, validator);

    /// <summary>
    /// Validates a detached COSE signature in memory.
    /// </summary>
    /// <param name="signature">The COSE signature stream to validate.</param>
    /// <param name="validator">A <see cref="CoseSign1MessageValidator"/> to validate the signature structure with, or <see cref="CoseSign1MessageValidator.None"/> to only check certificate validity and payload integrity.</param>
    /// <param name="payload">For detached signatures, the original payload that was signed; null for embedded signatures.</param>
    /// <exception cref="CoseValidationException">Validation failed</exception>
    /// <remarks>An <see cref="X509ChainTrustValidator"/> is recommended to ensure that the signing certificate chains to a valid root. You can also add an <see cref="X509CommonNameValidator"/> as a <see cref="CoseSign1MessageValidator.NextElement"/> to require a specific certificate Common Name.</remarks>
    public static ValidationResult Validate(
        Stream signature,
        CoseSign1MessageValidator validator,
        Stream? payload)
        => ValidateInternal(signature.GetBytes(), payloadBytes: null, payload, content: out _, validator);
    #endregion

    #region GetPayload Overloads
    /// <summary>
    /// Reads and decodes the original payload from an embedded COSE signature and validates the signature structure.
    /// </summary>
    /// <param name="signature">A byte array containing a COSE signature structure with embedded payload.</param>
    /// <param name="result">The results of signature validation.</param>
    /// <param name="roots">Optional. A set of root certificates to try to chain the signing certificate to during validation, in addition to the certificates installed on the host machine.</param>
    /// <param name="revocationMode">Optional. Revocation mode to use when validating the certificate chain.</param>
    /// <param name="requiredCommonName">Optional. Requires the signing certificate to match the specified Common Name.</param>
    /// <returns>The decoded payload as a string.</returns>
    public static string? GetPayload(
        byte[] signature,
        out ValidationResult result,
        List<X509Certificate2>? roots = null,
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        string? requiredCommonName = null)
        => GetPayload(signature, GetValidator(roots, revocationMode, requiredCommonName), out result);

    /// <summary>
    /// Reads and decodes the original payload from an embedded COSE signature and validates the signature structure.
    /// </summary>
    /// <param name="signature">A stream containing a COSE signature structure with embedded payload.</param>
    /// <param name="result">The results of signature validation.</param>
    /// <param name="roots">Optional. A set of root certificates to try to chain the signing certificate to during validation, in addition to the certificates installed on the host machine.</param>
    /// <param name="revocationMode">Optional. Revocation mode to use when validating the certificate chain.</param>
    /// <param name="requiredCommonName">Optional. Requires the signing certificate to match the specified Common Name.</param>
    /// <returns>The decoded payload as a string.</returns>
    public static string? GetPayload(
    Stream signature,
        out ValidationResult result,
        List<X509Certificate2>? roots = null,
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        string? requiredCommonName = null)
        => GetPayload(signature, GetValidator(roots, revocationMode, requiredCommonName), out result);

    /// <summary>
    /// Reads and decodes the original payload from an embedded COSE signature and validates the signature structure.
    /// </summary>
    /// <param name="signature">A byte array containing a COSE signature structure with embedded payload.</param>
    /// <param name="validator">A <see cref="CoseSign1MessageValidator"/> to validate the signature with, or <see cref="CoseSign1MessageValidator.None"/> to only check certificate validity and payload integrity.</param>
    /// <param name="result">The results of signature validation.</param>
    /// <returns>The decoded payload as a string.</returns>
    public static string? GetPayload(
    byte[] signature,
        CoseSign1MessageValidator validator,
        out ValidationResult result)
        => GetPayloadInternal(signature, validator, out result);

    /// <summary>
    /// Reads and decodes the original payload from an embedded COSE signature and validates the signature structure.
    /// </summary>
    /// <param name="signature">A stream containing a COSE signature structure with embedded payload.</param>
    /// <param name="validator">A <see cref="CoseSign1MessageValidator"/> to validate the signature with, or <see cref="CoseSign1MessageValidator.None"/> to only check certificate validity and payload integrity.</param>
    /// <param name="result">The results of signature validation.</param>
    /// <returns>A result object containing the original payload, as read and decoded from the embedded signature, and the validation results.</returns>
    public static string? GetPayload(
        Stream signature,
        CoseSign1MessageValidator validator,
        out ValidationResult result)
        => GetPayloadInternal(signature.GetBytes(), validator, out result);
    #endregion

    #region Internal Validation
    /// <summary>
    /// Validates a COSE signature structure.
    /// For detached signatures, include the payload in <paramref name="payloadBytes"/> or <paramref name="payloadStream"/> but not both.
    /// For embedded signatures, leave both payload fields <code>null</code>.
    /// </summary>
    /// <param name="signature">The COSE signature block.</param>
    /// <param name="payloadBytes">Optional. The original payload that was detach signed as a byte array.</param>
    /// <param name="payloadStream">Optional. The original payload that was detach signed as a Stream.</param>
    /// <param name="content">The unencrypted payload that was embed-signed if <paramref name="getPayload"/> is set; null otherwise.</param>
    /// <param name="validator">Optional. <see cref="CoseSign1MessageValidator"/> to validate the extracted CoseSign1Message object with.</param>
    /// <param name="getPayload">If set to true, retrieves the payload from an embedded signature structure.</param>
    /// <returns>A <seealso cref="ValidationResult"/> indicating success or failure.</returns>
    internal static ValidationResult ValidateInternal(
        ReadOnlyMemory<byte> signature,
        byte[]? payloadBytes,
        Stream? payloadStream,
        out ReadOnlyMemory<byte>? content,
        CoseSign1MessageValidator validator,
        bool getPayload = false)
    {
        // make sure we don't have conflicting payloads.
        if (payloadBytes is not null && payloadStream is not null)
        {
            throw new ArgumentException("Payload defined in two places.");
        }

        // List for collecting any validation errors we hit.
        List<ValidationFailureCode> errorCodes = new();

        // Load the signature content into a CoseSign1Message object.
        CoseSign1Message? msg = null;
        try
        {
            msg = CoseMessage.DecodeSign1(signature.ToArray());
        }
        catch (CryptographicException)
        {
            errorCodes.Add(ValidationFailureCode.SigningCertificateUnreadable);
            content = null;
            return new ValidationResult(false, errorCodes);
        }

        if (!msg.TryGetCertificateChain(out List<X509Certificate2>? chain, true))
        {
            errorCodes.Add(ValidationFailureCode.CertificateChainUnreadable);
            content = null;
            return new ValidationResult(false, errorCodes);
        }

        // Populate the output parameter
        content = getPayload ? msg.Content : null;

        // Validate trust of the signing certificate for the message if a CoseSign1MessageValidator was passed.
        if (!validator.TryValidate(msg, out List<CoseSign1ValidationResult> certValidationResults))
        {
            errorCodes.Add(ValidationFailureCode.TrustValidationFailed);
            return new ValidationResult(false, errorCodes, certValidationResults, chain);
        }

        // Get the signing certificate
        if (!msg.TryGetSigningCertificate(out X509Certificate2? signingCertificate, true) || signingCertificate is null)
        {
            errorCodes.Add(ValidationFailureCode.CertificateChainUnreadable); // Is this always correct? Can there be certs found with none of them being the signing cert?
            return new ValidationResult(false, errorCodes, certValidationResults, chain);
        }

        // Get the public key
        AsymmetricAlgorithm? publicKey = ((AsymmetricAlgorithm?)signingCertificate.GetRSAPublicKey()
            ?? signingCertificate.GetECDsaPublicKey());

        if (publicKey is null)
        {
            errorCodes.Add(ValidationFailureCode.NoPublicKey);
            return new ValidationResult(false, errorCodes, certValidationResults, chain);
        }

        // Validate that the COSE header is formatted correctly and that the payload and hash are consistent.
        bool messageVerified = false;

        // Checks for an indirect signature, where the content header contains the hash of the payload, and the algorithm is stored in the message.
        // If this is the case, we need to make sure the external payload hash matches the hash stored in the cose message content.
        bool indirectSignature = msg.IsDetachedSignature();
        try
        {

            if (!payloadBytes.IsNullOrEmpty())
            {
                if (indirectSignature)
                {
                    // Indirect signature, hash embedded in the COSE message
                    messageVerified = (msg.VerifyEmbedded(publicKey) && msg.SignatureMatches(payloadBytes));
                }
                else
                {
                    // Detached payload received as byte array
                    messageVerified = msg.VerifyDetached(publicKey, new ReadOnlySpan<byte>(payloadBytes));
                }
            }
            else if (payloadStream is not null)
            {
                if (indirectSignature)
                {
                    // Indirect signature, hash embedded in the COSE message
                    messageVerified = (msg.VerifyEmbedded(publicKey) && msg.SignatureMatches(payloadStream));
                }
                else
                {
                    // Detached payload received as a stream
                    messageVerified = Task.Run(() => msg.VerifyDetachedAsync(publicKey, payloadStream)).GetAwaiter().GetResult();
                }
            }
            else
            {
                // Embedded payload
                messageVerified = msg.VerifyEmbedded(publicKey);
            }

            if (!messageVerified)
            {
                errorCodes.Add(ValidationFailureCode.PayloadMismatch);
            }
        }

        // There are other exceptions that could be thrown here but the earlier validation steps should have caught them.
        catch (CryptographicException)
        {
            errorCodes.Add(ValidationFailureCode.CoseHeadersInvalid);
        }
        catch (InvalidOperationException)
        {
            errorCodes.Add(
                payloadBytes is null && payloadStream is null ? ValidationFailureCode.PayloadMissing :
                ValidationFailureCode.RedundantPayload);
        }
        
        return new ValidationResult(messageVerified, errorCodes, certValidationResults, chain);
    }

    /// <summary>
    /// Reads and decodes the original payload from an embedded COSE signature and validates the signature structure.
    /// </summary>
    /// <param name="signature">A COSE signature structure with embedded payload.</param>
    /// <param name="validator">A <see cref="CoseSign1MessageValidator"/> to validate the signature with, or <see cref="CoseSign1MessageValidator.None"/> to only check certificate validity and payload integrity.</param>
    /// <param name="result">The results of signature validation.</param>
    /// <returns>The decoded payload as a string.</returns>
    internal static string? GetPayloadInternal(
        ReadOnlyMemory<byte> signature,
        CoseSign1MessageValidator validator,
        out ValidationResult result)
    {
        result = ValidateInternal(
            signature, payloadBytes: null, payloadStream: null, out ReadOnlyMemory<byte>? payloadBytes,
            validator, getPayload: true);
        string? content = null;
        if (payloadBytes is null)
        {
            result.AddError(ValidationFailureCode.PayloadUnreadable);
            result.Success = false;
        }
        else
        {
            content = Encoding.UTF8.GetString(payloadBytes.Value.ToArray());
        }

        return content;
    }
    #endregion

    /// <summary>
    /// Checks the local Certificate Store for a certificate matching the specified thumbprint.
    /// </summary>
    /// <param name="thumbprint">The SHA1 thumbprint of the certificate to find.</param>
    /// <param name="storeName">(Optional) The name of the store to check. Default value is 'My'.</param>
    /// <param name="storeLocation">(Optional) The location of the store to check. Default value is CurrentUser.</param>
    /// <returns>The certificate, if found.</returns>
    /// <exception cref="CoseSign1CertificateException">The certificate could not be found in the specified store.</exception>
    /// <remarks>This method takes StoreName as a string to allow for custom stores.</remarks>
    public static X509Certificate2 LookupCertificate(string thumbprint, string storeName = DefaultStoreName, StoreLocation storeLocation = StoreLocation.CurrentUser)
    {
        try
        {
            // Open the cert store
            using X509Store certStore = new(storeName, storeLocation);
            certStore.Open(OpenFlags.ReadOnly);

            // Return the first certificate that matches the thumbprint, if any
            return certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false)
                ?.FirstOrDefault()
                ?? throw new CoseSign1CertificateException($"Unable to find certificate with thumbprint {thumbprint}");
        }
        catch (SecurityException)
        {
            throw new CoseSign1CertificateException(
                $"User {Environment.GetEnvironmentVariable("username")} does not have the required permission to access the certificate store.");
        }
        catch (CryptographicException ex)
        {
            throw new CoseSign1CertificateException(
                $"The certificate store {storeName} / {Enum.GetName(typeof(StoreLocation), storeLocation)} could not be opened.", ex);
        }
    }

    #region private helper methods
    // Generates a CoseSign1MessageValidator object from supplied parameters. At minimum, a chain trust validator is generated on default roots.
    internal static CoseSign1MessageValidator GetValidator(
        List<X509Certificate2>? roots = null,
        X509RevocationMode revocationMode = X509RevocationMode.Online,
        string? requiredCommonName = null,
        bool allowUntrusted = false)
    {
        // Create a validator for the certificate trust chain.
        CoseSign1MessageValidator chainTrustValidator = new X509ChainTrustValidator(
                roots,
                revocationMode,
                allowUnprotected: true,
                allowUntrusted: allowUntrusted);

        // If validating CommonName, we'll do that first, and set it to call for chain trust validation when it finishes.
        if (!string.IsNullOrWhiteSpace(requiredCommonName))
        {
#pragma warning disable CS8604 // Possible null reference argument. This should not be thrown because we're checking for null or whitespace above.
            X509CommonNameValidator commonNameValidator = new(requiredCommonName, allowUnprotected: true)
            {
                NextElement = chainTrustValidator
            };
#pragma warning restore CS8604 // Possible null reference argument.

            return commonNameValidator;
        }

        return chainTrustValidator;
    }

    #endregion
}
