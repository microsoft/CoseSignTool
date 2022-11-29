// ---------------------------------------------------------------------------
// <copyright file="CoseParser.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseX509
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Formats.Cbor;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.Cose;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Contains static methods to generate and validate Cose X509 signatures.
    /// </summary>
    public static class CoseParser
    {
        #region Validate
        /// <summary>
        /// Validates a detached COSE signature against a source file and the specified set of root certificates in the local Windows Certificate Store.
        /// </summary>
        /// <param name="signatureFile">The COSE signature file to validate.</param>
        /// <param name="payloadFile">The source file containing the original payload.</param>
        /// <param name="thumbprints">Required. A list of SHA1 thumbprints of installed certificates to try to chain to.</param>
        /// <param name="storeName">Optional. The name of the certificate store that contains certificates to try to chain to. Default is "My".</param>
        /// <param name="storeLocation">Optional. The location of the certificate store that contains certificates to try to chain to. Default is "CurrentUser".</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static void Validate(
            string signatureFile,
            string payloadFile,
            List<string> thumbprints,
            string storeName = "My",
            StoreLocation storeLocation = StoreLocation.CurrentUser,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => Validate(
                signatureFile,
                payloadFile,
                CertificateStoreHelper.LookupCertificates(thumbprints, storeName, storeLocation),
                revocationMode,
                requiredCommonName,
                allowUntrusted);

        /// <summary>
        /// Validates a detached COSE signature against a source file and the supplied set of root certificates.
        /// </summary>
        /// <param name="signatureFile">The COSE signature file to validate.</param>
        /// <param name="payloadFile">The source file containing the original payload.</param>
        /// <param name="roots">Required. The set of roots the signing cert must try to chain to.</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static void Validate(string signatureFile,
            string payloadFile,
            List<X509Certificate2> roots,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => ValidateInternal(ReadFileContent(signatureFile),
                ReadFileContent(payloadFile),
                roots,
                revocationMode,
                requiredCommonName,
                allowUntrusted);

        /// <summary>
        /// Validates a detached COSE signature against a source file and whatever certificates are installed in the Windows certificate store.
        /// </summary>
        /// <param name="signatureFile">The COSE signature file to validate.</param>
        /// <param name="payloadFile">The source file containing the original payload.</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static void Validate(string signatureFile,
            string payloadFile,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => ValidateInternal(ReadFileContent(signatureFile),
                ReadFileContent(payloadFile),
                null,
                revocationMode,
                requiredCommonName,
                allowUntrusted);

        /// <summary>
        /// Validates an embedded COSE signature on a file against a specified set of root certificates in the Windows Certificate Store.
        /// </summary>
        /// <param name="SignatureFile">The COSE embed-signed file to validate.</param>
        /// <param name="thumbprints">Required. A list of SHA1 thumbprints of installed certificates to try to chain to.</param>
        /// <param name="storeName">Optional. The name of the certificate store that contains certificates to try to chain to. Default is "My".</param>
        /// <param name="storeLocation">Optional. The location of the certificate store that contains certificates to try to chain to. Default is "CurrentUser".</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static void Validate(
            string SignatureFile,
            List<string> thumbprints,
            string storeName = "My",
            StoreLocation storeLocation = StoreLocation.CurrentUser,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => Validate(
                SignatureFile,
                CertificateStoreHelper.LookupCertificates(thumbprints, storeName, storeLocation),
                revocationMode,
                requiredCommonName,
                allowUntrusted);

        /// <summary>
        /// Validates an embedded COSE signature on a file against the supplied set of root certificates.
        /// </summary>
        /// <param name="SignatureFile">The COSE embed-signed file to validate.</param>
        /// <param name="roots">Required. The set of roots the signing cert must chain to.</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static void Validate(string SignatureFile,
            List<X509Certificate2> roots,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => ValidateInternal(
                ReadFileContent(SignatureFile),
                null,
                roots,
                revocationMode,
                requiredCommonName,
                allowUntrusted);

        /// <summary>
        /// Validates an embedded COSE signature on a file against whatever certificates are installed in the Windows certificate store.
        /// </summary>
        /// <param name="SignatureFile">The COSE embed-signed file to validate.</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static void Validate(string SignatureFile,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => ValidateInternal(ReadFileContent(SignatureFile),
                null,
                null,
                revocationMode,
                requiredCommonName,
                allowUntrusted);
        #endregion

        #region TryValidate
        /// <summary>
        /// Tries to validate a detached COSE signature against a source file and the specified set of root certificates in the local Windows Certificate Store.
        /// </summary>
        /// <param name="signatureFile">The COSE signature file to validate.</param>
        /// <param name="payloadFile">The source file containing the original payload.</param>
        /// <param name="thumbprints">A list of SHA1 thumbprints of installed certificates to try to chain to.</param>
        /// <param name="ex">The exception thrown on validation if any.</param>
        /// <param name="storeName">Optional. The name of the certificate store that contains certificates to try to chain to. Default is "My".</param>
        /// <param name="storeLocation">Optional. The location of the certificate store that contains certificates to try to chain to. Default is "CurrentUser".</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <returns>True on success, false on failure.</returns>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static bool TryValidate(string signatureFile,
            string payloadFile,
            List<string> thumbprints,
            out Exception? ex,
            string storeName = "My",
            StoreLocation storeLocation = StoreLocation.CurrentUser,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => TryValidate(signatureFile,
                payloadFile,
                CertificateStoreHelper.LookupCertificates(thumbprints, storeName, storeLocation),
                out ex,
                revocationMode,
                requiredCommonName,
                allowUntrusted);

        /// <summary>
        /// Tries to validate a detached COSE signature against a source file and the supplied set of root certificates.
        /// </summary>
        /// <param name="signatureFile">The COSE signature file to validate.</param>
        /// <param name="payloadFile">The source file containing the original payload.</param>
        /// <param name="roots">The set of roots the signing cert must try to chain to.</param>
        /// <param name="ex">The exception thrown on validation if any.</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <returns>True on success, false on failure.</returns>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static bool TryValidate(
            string signatureFile,
            string payloadFile,
            List<X509Certificate2> roots,
            out Exception? ex,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => TryValidateInternal(
                ReadFileContent(signatureFile),
                ReadFileContent(payloadFile),
                roots,
                out ex,
                out _,
                revocationMode,
                requiredCommonName,
                allowUntrusted);

        /// <summary>
        /// Tries to validate a detached COSE signature against a source file and whatever certificates are installed in the Windows certificate store.
        /// </summary>
        /// <param name="signatureFile">The COSE signature file to validate.</param>
        /// <param name="payloadFile">The source file containing the original payload.</param>
        /// <param name="ex">The exception thrown on validation if any.</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <returns>True on success, false on failure.</returns>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static bool TryValidate(
            string signatureFile,
            string payloadFile,
            out Exception? ex,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => TryValidateInternal(
                ReadFileContent(signatureFile),
                ReadFileContent(payloadFile),
                null,
                out ex,
                out _,
                revocationMode,
                requiredCommonName,
                allowUntrusted);

        /// <summary>
        /// Tries to validate an embedded COSE signature on a file against a specified set of root certificates in the Windows Certificate Store.
        /// </summary>
        /// <param name="SignatureFile">The COSE embed-signed file to validate.</param>
        /// <param name="thumbprints">A list of SHA1 thumbprints of installed certificates to try to chain to.</param>
        /// <param name="ex">The exception thrown on validation if any.</param>
        /// <param name="storeName">Optional. The name of the certificate store that contains certificates to try to chain to. Default is "My".</param>
        /// <param name="storeLocation">Optional. The location of the certificate store that contains certificates to try to chain to. Default is "CurrentUser".</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <returns>True on success, false on failure.</returns>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static bool TryValidate(string SignatureFile,
            List<string> thumbprints,
            out Exception? ex,
            string storeName = "My",
            StoreLocation storeLocation = StoreLocation.CurrentUser,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => TryValidate(SignatureFile,
                CertificateStoreHelper.LookupCertificates(thumbprints, storeName, storeLocation),
                out ex,
                revocationMode,
                requiredCommonName,
                allowUntrusted);

        /// <summary>
        /// Tries to validate an embedded COSE signature on a file against the supplied set of root certificates.
        /// </summary>
        /// <param name="SignatureFile">The COSE embed-signed file to validate.</param>
        /// <param name="roots">The set of roots the signing cert must chain to.</param>
        /// <param name="ex">The exception thrown on validation if any.</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <returns>True on success, false on failure.</returns>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static bool TryValidate(
            string SignatureFile,
            List<X509Certificate2> roots,
            out Exception? ex,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => TryValidateInternal(
                ReadFileContent(SignatureFile),
                null,
                roots,
                out ex,
                out _,
                revocationMode,
                requiredCommonName,
                allowUntrusted);

        /// <summary>
        /// Tries to validate an embedded COSE signature on a file against whatever certificates are installed in the Windows certificate store.
        /// </summary>
        /// <param name="SignatureFile">The COSE embed-signed file to validate.</param>
        /// <param name="roots">The set of roots the signing cert must chain to.</param>
        /// <param name="ex">The exception thrown on validation if any.</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <returns>True on success, false on failure.</returns>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static bool TryValidate(
            string SignatureFile,
            out Exception? ex,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => TryValidateInternal(
                ReadFileContent(SignatureFile),
                null,
                null,
                out ex,
                out _,
                revocationMode,
                requiredCommonName,
                allowUntrusted);
        #endregion

        #region GetPayload
        /// <summary>
        /// Validates an embedded COSE signature on a file against a specified set of root certificates in the Windows Certificate Store and returns a copy
        /// of the original payload.
        /// </summary>
        /// <param name="SignatureFile">The COSE embed-signed file to validate.</param>
        /// <param name="thumbprints">A list of SHA1 thumbprints of installed certificates to try to chain to.</param>
        /// <param name="storeName">Optional. The name of the certificate store that contains certificates to try to chain to. Default is "My".</param>
        /// <param name="storeLocation">Optional. The location of the certificate store that contains certificates to try to chain to. Default is "CurrentUser".</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <returns>A copy of the original payload content as a byte array.</returns>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static byte[]? GetPayload(
            string SignatureFile,
            List<string> thumbprints,
            string storeName = "My",
            StoreLocation storeLocation = StoreLocation.CurrentUser,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => GetPayload(
                SignatureFile,
                CertificateStoreHelper.LookupCertificates(thumbprints, storeName, storeLocation),
                revocationMode,
                requiredCommonName,
                allowUntrusted);

        /// <summary>
        /// Validates an embedded COSE signature on a file against the supplied set of root certificates and returns a copy
        /// of the original payload.
        /// </summary>
        /// <param name="SignatureFile">The COSE embed-signed file to validate.</param>
        /// <param name="roots">The set of roots the signing cert must chain to.</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <returns>A copy of the original payload content as a byte array.</returns>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static byte[]? GetPayload(
            string SignatureFile,
            List<X509Certificate2>? roots,
            [NotNull] X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => ValidateInternal(
                ReadFileContent(SignatureFile),
                null,
                roots,
                revocationMode,
                requiredCommonName,
                allowUntrusted,
                true);

        /// <summary>
        /// Validates an embedded COSE signature on a file against a specified set of root certificates in the Windows Certificate Store and returns a copy
        /// of the original payload.
        /// </summary>
        /// <param name="SignatureFile">The COSE embed-signed file to validate.</param>
        /// <param name="thumbprints">A list of SHA1 thumbprints of installed certificates to try to chain to.</param>
        /// <param name="storeName">Optional. The name of the certificate store that contains certificates to try to chain to. Default is "My".</param>
        /// <param name="storeLocation">Optional. The location of the certificate store that contains certificates to try to chain to. Default is "CurrentUser".</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <returns>A copy of the original payload content as a byte array.</returns>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static bool TryGetPayload(
            string SignatureFile,
            List<string> thumbprints,
            out byte[]? payload,
            out Exception? ex,
            string storeName = "My",
            StoreLocation storeLocation = StoreLocation.CurrentUser,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => TryGetPayload(
                SignatureFile,
                CertificateStoreHelper.LookupCertificates(thumbprints, storeName, storeLocation),
                out payload,
                out ex,
                revocationMode,
                requiredCommonName,
                allowUntrusted);

        /// <summary>
        /// Validates an embedded COSE signature on a file against the supplied set of root certificates and returns a copy
        /// of the original payload.
        /// </summary>
        /// <param name="SignatureFile">The COSE embed-signed file to validate.</param>
        /// <param name="roots">The set of roots the signing cert must chain to.</param>
        /// <param name="revocationMode">Optional. Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <returns>A copy of the original payload content as a byte array.</returns>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        public static bool TryGetPayload(string SignatureFile,
            List<X509Certificate2> roots,
            out byte[]? payload,
            out Exception? ex,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false)
            => TryValidateInternal(ReadFileContent(SignatureFile),
                null,
                roots,
                out ex,
                out payload,
                revocationMode,
                requiredCommonName,
                allowUntrusted,
                true);
        #endregion

        #region Internal Validation
        /// <summary>
        /// Validates a COSE signature on a file.
        /// </summary>
        /// <param name="signed">The content of the file with the signature block.</param>
        /// <param name="payloadFromFile">The content of the payload file if it was detached-signed. If embed-signed, leave this value as null.</param>
        /// <param name="roots">The set of roots the signing cert must chain to</param>
        /// <param name="revocationMode">Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <param name="getPayload">Retrieves the payload from an embed-signed file.</param>
        /// <returns>A copy of the original payload if getPayloadOutput set; null otherwise.</returns>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        internal static byte[]? ValidateInternal(
            ReadOnlyMemory<byte> signed,
            byte[]? payloadFromFile,
            List<X509Certificate2>? roots,
            X509RevocationMode revocationMode,
            string? requiredCommonName,
            bool allowUntrusted = false,
            bool getPayload = false)
        {
            var externalPayload = new ReadOnlySpan<byte>(payloadFromFile);

            var policy = new X509ChainPolicy()
            {
                RevocationMode = revocationMode,
            };

            if (roots != null && roots.Count > 0)
            {
                // Validate the cert chain against the supplied set of roots.
                policy.CustomTrustStore.AddRange(roots.ToArray());
                policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            }

            if (allowUntrusted)
            {
                policy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            }

            // Load the signed content into a CoseSign1Message object.
            CoseSign1Message msg = CoseMessage.DecodeSign1(signed.ToArray());

            // Validate
            if (!msg.VerifyWithX509(externalPayload, out X509ChainStatus[]? status, policy, requiredCommonName))
            {
                CoseValidationException ex = (status is null) ?
                    new CoseValidationException("Cryptographic validation of signature failed.") :
                    new CoseValidationException("Cryptographic validation of signature failed to create valid certificate chain.", status);
                throw ex;
            }

            return getPayload ? msg.Content?.ToArray() : null;
        }

        /// <summary>
        /// Tries to validate a COSE signature on a file.
        /// </summary>
        /// <param name="signed">The content of the file with the signature block.</param>
        /// <param name="payload">The content that was signed.</param>
        /// <param name="roots">The set of roots the signing cert must chain to</param>
        /// <param name="ex">The exception thrown on validation if any.</param>
        /// <param name="payloadOutput">The payload output from an embed-signed file if requested.</param>
        /// <param name="revocationMode">Revocation mode to use when validating certificate chain.</param>
        /// <param name="requiredCommonName">Optional. Common name the signing certificate must have.</param>
        /// <param name="allowUntrusted">Optional. Allows validation to succeed even when the signing certificate does not chain to a trusted root.</param>
        /// <param name="getPayload">Retrieves the payload from an embed-signed file.</param>
        /// <returns>A copy of the original payload if getPayloadOutput set; null otherwise.</returns>
        /// <exception cref="CoseValidationException">Validation failed</exception>
        internal static bool TryValidateInternal(
            ReadOnlyMemory<byte> signed,
            byte[]? payload,
            List<X509Certificate2>? roots,
            [NotNullWhen(returnValue: false)] out Exception? ex,
            out byte[]? payloadOutput,
            X509RevocationMode revocationMode = X509RevocationMode.Online,
            string? requiredCommonName = null,
            bool allowUntrusted = false,
            bool getPayload = false)
        {
            payloadOutput = null;
            ex = null;
            try
            {
                payloadOutput = ValidateInternal(signed, payload, roots, revocationMode, requiredCommonName, allowUntrusted, getPayload);
                return true;
            }
            catch (Exception e)
            {
                ex = e;
                return false;
            }
        }
        #endregion

        #region Sign
        /// <summary>
        /// Signs a file using a certificate from the local Windows Certificate Store.
        /// The signature file is separate from the file to sign.
        /// </summary>
        /// <param name="payloadFile">The file to sign.</param>
        /// <param name="thumbprint">The SHA1 thumbprint of an installed certificate to sign with.</param>
        /// <param name="embedPayload">True to embed an encoded copy of the payload content into the signature file.</param>
        /// <param name="signatureFile">.Optional. The name and path to write the signature file to. 
        /// Default value is [payloadFile].cose, or [payloadFile].csm if embedPayload is true.</param>
        /// <param name="storeName">Optional. The name of the certificate store that contains the signing certificate. Default is "My".</param>
        /// <param name="storeLocation">Optional. The location of the certificate store that contains the signing certificate. Default is "CurrentUser".</param>
        /// <param name="roots"/>A set of certificates to try to chain to when not using the Windows Certificate Store.
        /// <exception cref="CoseSigningException">Unsupported certificate type for COSE signing, or the certificate chain could not be built.</exception>
        /// <exception cref="CryptographicException">The signing certificate or one or more declared additional certificates are null or invalid.</exception>
        public static void Sign(string payloadFile,
            string thumbprint,
            bool embedPayload = false,
            string? signatureFile = null,
            string storeName = "My",
            StoreLocation storeLocation = StoreLocation.CurrentUser,
            IEnumerable<X509Certificate2>? roots = null)
            => Sign(payloadFile,
                CertificateStoreHelper.LookupCertificate(thumbprint, storeName, storeLocation),
                embedPayload,
                signatureFile,
                roots);

        /// <summary>
        /// Signs a file with the supplied certificate.
        /// The signature file is separate from the file to sign.
        /// </summary>
        /// <param name="payloadFile">The file to sign.</param>
        /// <param name="certificate">The certificate to sign with.</param>
        /// <param name="embedPayload">True to embed an encoded copy of the payload content into the signature file.</param>
        /// <param name="signatureFile">.Optional. The name and path to write the signature file to.
        /// Default value is [payloadFile].cose, or [payloadFile].csm if embedPayload is true.</param>
        /// <param name="roots"/>A set of certificates to try to chain to when not using the Windows Certificate Store.
        /// <exception cref="CoseSigningException">Unsupported certificate type for COSE signing, or the certificate chain could not be built.</exception>
        /// <exception cref="CryptographicException">The signing certificate or one or more declared additional certificates are null or invalid.</exception>
        public static void Sign(
            string payloadFile,
            X509Certificate2 certificate,
            bool embedPayload = false,
            string? signatureFile = null,
            IEnumerable<X509Certificate2>? roots = null)
            => Sign(
                ReadFileContent(payloadFile),
                embedPayload,
                certificate,
                signatureFile ?? GetDefaultFileName(payloadFile, embedPayload),
                roots);

        /// <summary>
        /// Signs a file with the supplied certificate.
        /// The signature file is separate from the file to sign.
        /// </summary>
        /// <param name="payloadBytes">The file content to be signed.</param>
        /// <param name="embedPayload">True to embed an encoded copy of the payload content into the signature file.</param>
        /// <param name="certificate">The certificate to sign with.</param>
        /// <param name="signatureFile">The name and path to write the signature file to.
        /// Default value is [payloadFile].cose, or [payloadFile].csm if embedPayload is true.</param>
        /// <param name="roots"/>A set of certificates to try to chain to when not using the Windows Certificate Store.
        /// <exception cref="CoseSigningException">Unsupported certificate type for COSE signing, or the certificate chain could not be built.</exception>
        /// <exception cref="CryptographicException">The signing certificate or one or more declared additional certificates are null or invalid.</exception>
        public static void Sign(ReadOnlyMemory<byte> payloadBytes,
            bool embedPayload,
            X509Certificate2 certificate,
            string signatureFile,
            IEnumerable<X509Certificate2>? roots = null)
        {
            roots ??= new List<X509Certificate2>();

            try
            {
                var signedBytes = CreateCoseSignature(payloadBytes, embedPayload, certificate, HashAlgorithmName.SHA256, roots);

                File.WriteAllBytes(signatureFile, signedBytes.ToArray());
            }
            catch (SystemException ex) when (ex is ArgumentException or InvalidOperationException)
            {
                throw new CryptographicException("The signing certificate is null or invalid.", ex);
            }
        }
        #endregion

        #region TrySign
        /// <summary>
        /// Tries to sign a file using a certificate from the local Windows Certificate Store.
        /// The signature file is separate from the file to sign.
        /// </summary>
        /// <param name="payloadFile">The file to sign.</param>
        /// <param name="thumbprint">The SHA1 thumbprint of an installed certificate to sign with.</param>
        /// <param name="ex">The exception thrown on validation if any.</param>
        /// <param name="embedPayload">True to embed an encoded copy of the payload content into the signature file.</param>
        /// <param name="signatureFile">.Optional. The name and path to write the signature file to. 
        /// Default value is [payloadFile].cose, or [payloadFile].csm if embedPayload is true.</param>
        /// <param name="storeName">Optional. The name of the certificate store that contains the signing certificate. Default is "My".</param>
        /// <param name="storeLocation">Optional. The location of the certificate store that contains the signing certificate. Default is "CurrentUser".</param>
        /// <param name="roots"/>A set of certificates to try to chain to when not using the Windows Certificate Store.
        public static bool TrySign(
            string payloadFile,
            string thumbprint,
            out Exception? ex,
            bool embedPayload = false,
            string? signatureFile = null,
            string storeName = "My",
            StoreLocation storeLocation = StoreLocation.CurrentUser,
            IEnumerable<X509Certificate2>? roots = null)
            => TrySign(payloadFile,
                CertificateStoreHelper.LookupCertificate(thumbprint, storeName, storeLocation),
                out ex,
                embedPayload,
                signatureFile,
                roots);

        /// <summary>
        /// Tries to sign a file with the supplied certificate.
        /// The signature file is separate from the file to sign.
        /// </summary>
        /// <param name="payloadFile">The file to sign.</param>
        /// <param name="certificate">The certificate to sign with.</param>
        /// <param name="ex">The exception thrown on validation if any.</param>
        /// <param name="embedPayload">True to embed an encoded copy of the payload content into the signature file.</param>
        /// <param name="signatureFile">.Optional. The name and path to write the signature file to. 
        /// Default value is [payloadFile].cose, or [payloadFile].csm if embedPayload is true.</param>
        /// <param name="roots"/>A set of certificates to try to chain to when not using the Windows Certificate Store.
        public static bool TrySign(string payloadFile,
            X509Certificate2 certificate,
            out Exception? ex,
            bool embedPayload = false,
            string? signatureFile = null,
            IEnumerable<X509Certificate2>? roots = null)
            => TrySignInternal(
                ReadFileContent(payloadFile),
                embedPayload,
                certificate,
                signatureFile ?? GetDefaultFileName(payloadFile, embedPayload),
                out ex,
                roots);
        #endregion

        #region Internal Signing
        /// <summary>
        /// Tries to sign a file with the supplied certificate.
        /// </summary>
        /// <param name="payload">The file content to be signed.</param>
        /// <param name="embedPayload">True to embed an encoded copy of the payload in the signature file. False to create the signature file with only a hash of the payload.</param>
        /// <param name="signingCertificate">The certificate to sign with.</param>
        /// <param name="SignatureFile">The name and path to write the signed file to.</param>
        /// <param name="ex">The exception thrown on validation if any.</param>
        /// <param name="roots"></param>
        /// <returns>True on success, false otherwise.</returns>
        internal static bool TrySignInternal(
            ReadOnlyMemory<byte> payload,
            bool embedPayload,
            X509Certificate2 signingCertificate,
            string SignatureFile,
            [NotNullWhen(returnValue: false)] out Exception? ex,
            IEnumerable<X509Certificate2>? roots = null)
        {
            ex = null;
            try
            {
                Sign(payload, embedPayload, signingCertificate, SignatureFile, roots);
                return true;
            }
            catch (Exception e)
            {
                ex = e;
                return false;
            }
        }

        /// <summary>
        /// Creates a COSE signature structure in memory that, if written to a file, constitutes signing the payload.
        /// </summary>
        /// <param name="payload">The content of the file to sign.</param>
        /// <param name="embedPayload">True to embed an encoded copy of the payload in the signature structure. By default, this method assumes detached signing, where the signature matches the original file by hash.</param>
        /// <param name="signingCertificate">The certificate to sign with.</param>
        /// <param name="hashAlgorithm">The CNG-compliant hash algorithm to use; usually SHA256 or MD5.</param>
        /// <param name="roots">The collection of root certificates to try to chain to if not using the Windows Certificate Store.</param>
        /// <returns>A COSE x509 signature structure that can be used to sign the file the payload originated from.</returns>
        /// <exception cref="CoseSigningException">Unsupported certificate type for COSE signing, or the certificate chain could not be built.</exception>
        /// <exception cref="InvalidOperationException">The signing certificate has an invalid header.</exception>
        /// <exception cref="ArgumentException">The signing certificate is null or invalid.</exception>
        /// <exception cref="CryptographicException">One or more declared roots are null or invalid.</exception>
        internal static ReadOnlyMemory<byte> CreateCoseSignature(
            ReadOnlyMemory<byte> payload,
            bool embedPayload,
            X509Certificate2 signingCertificate,
            HashAlgorithmName hashAlgorithm,
            IEnumerable<X509Certificate2>? roots = null)
        {
            // The COSE API doesn't allow signing without the root present (though self-signed is fine)
            // This is different from validation, where the roots can be extracted from the signature file.
            X509Chain chain = signingCertificate.GetChain(false, roots?.ToArray()); // Can throw here
            roots ??= new List<X509Certificate2>();

            CborWriter cborWriter = new(CborConformanceMode.Strict);
            CoseHeaderMap protectedHeaders = new();
            CoseHeaderMap unprotectedHeaders = new();

            // Encode signing cert
            CoseX509Thumprint thumbprint = new(signingCertificate);
            var encodedBytes = thumbprint.Serialize(cborWriter);
            protectedHeaders.SetEncodedValue(Labels.labelx5t, encodedBytes);

            // TODO: Update System.Formats.Cbor and System.Security.Cryptography.Cose after they officially release a final version and it's documented.
            // This will break deserialization because newer versions change the CoseHeaderMap data structure among other things, so it will take some
            // careful adjustment in the encoding steps.

            // Encode signing cert chain
            var cosex509certchain = ReverseChainOrder(chain);
            cborWriter.EncodeCertList(cosex509certchain);
            protectedHeaders.SetEncodedValue(Labels.labelx5chain, cborWriter.Encode());

            // Encode additional certs
            cborWriter.EncodeCertList(roots.ToList());
            protectedHeaders.SetEncodedValue(Labels.labelx5bag, cborWriter.Encode());

            // Get the signing algorithm
            AsymmetricAlgorithm algKey = signingCertificate.GetRSAPrivateKey() ?? signingCertificate.GetECDsaPrivateKey() as AsymmetricAlgorithm
                ?? throw new CoseSigningException("Unsupported certificate type for COSE signing.");

            // Sign the payload
            return CoseSign1Message.Sign(payload.ToArray(), protectedHeaders, unprotectedHeaders, algKey, hashAlgorithm, !embedPayload);
        }
        #endregion

        #region private helper methods
        private static byte[] ReadFileContent(string? fileName)
        {
            if (fileName == null)
            {
                throw new ArgumentNullException(nameof(fileName), "No file specified.");
            }
            return File.Exists(fileName) ? File.ReadAllBytes(fileName)
            : throw new FileNotFoundException(nameof(fileName));
        }

        private static string GetDefaultFileName(string payloadFile, bool embedPayload) => payloadFile + (embedPayload ? ".csm" : ".cose");

        // Reverses the order of certificates in an X509Chain to put the leaf node last for CBOR encoding
        internal static Stack<X509Certificate2> ReverseChainOrder(X509Chain certChain)
        {
            var coseX509CertChain = new Stack<X509Certificate2>();

            foreach (X509ChainElement chainElement in certChain.ChainElements)
            {
                coseX509CertChain.Push(chainElement.Certificate);
            }

            return coseX509CertChain;
        }
        #endregion
    }
}
