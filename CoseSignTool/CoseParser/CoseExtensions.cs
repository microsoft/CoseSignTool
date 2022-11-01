// ----------------------------------------------------------------------------------------
// <copyright file="CoseExtensions.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseX509
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Formats.Cbor;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.Cose;
    using System.Security.Cryptography.X509Certificates;

    public static class CoseExtensions
    {
        #region CoseSign1Message extensions
        /// <summary>
        /// Validates the structure, content, and certificate chain of the current CoseSign1Message object.
        /// </summary>
        /// <param name="msg">The current CoseSign1Message object.</param>
        /// <param name="content">The content of an external payload file if any.</param>
        /// <param name="policy">An optional X509 chain policy to use when getting the signing certificate.</param>
        /// <param name="requiredCommonName">Sets a specific certificate Common Name that the signing certificate must match.</param>
        /// <returns>True if all verification checks succeed; false otherwise.</returns>
        public static bool VerifyWithX509(this CoseSign1Message msg, ReadOnlySpan<byte> content, X509ChainPolicy? policy = null, string? requiredCommonName = null)
        {
            X509Certificate2 signingCert = null;
            try
            {
                if (msg.TryGetSigningCertificate(out signingCert, out _, policy))
                {
                    signingCert.ValidateCommonName(requiredCommonName);

                    var rsaKey = signingCert.GetRSAPublicKey();
                    var ecKey = signingCert.GetECDsaPublicKey();

                    if (rsaKey is not null)
                    {
                        return content.IsEmpty ? msg.Verify(rsaKey) : msg.Verify(rsaKey, content);
                    }
                    else if (ecKey is not null)
                    {
                        return content.IsEmpty ? msg.Verify(ecKey) : msg.Verify(ecKey, content);
                    }

                    return false;
                }
            }

            finally
            {
                if (signingCert is not null)
                {
                    signingCert.Dispose();
                }
            }
            return false;
        }

        /// <summary>
        /// Tries to get the leaf node certificate of the current CoseSign1Message object.
        /// </summary>
        /// <param name="msg">The current CoseSign1Message object.</param>
        /// <param name="signingCert">The leaf node signing certificate if found.</param>
        /// <param name="extraCerts">Any additional certificates that are part of the certificate chain if found.</param>
        /// <param name="policy">An optional x509 chain policy to enforce.</param>
        /// <returns>True if there is a signing certificate and it is part of a valid certificate chain, even if it is a chain of 1; false otherwise.</returns>
        /// <exception cref="CoseX509FormatException">The certificates could not be read from the header.</exception>
        /// <exception cref="CryptographicException">A signing certificate was found but a certificate chain could not be built from it.</exception>
        public static bool TryGetSigningCertificate(this CoseSign1Message msg, [NotNullWhen(returnValue: true)] out X509Certificate2? signingCert, out X509Certificate2Collection extraCerts, X509ChainPolicy? policy = null)
        {
            signingCert = null;
            extraCerts = new X509Certificate2Collection();
            var chainCerts = new X509Certificate2Collection();
            CoseX509Thumprint? thumbprint = null;

            try
            {
                policy ??= new X509ChainPolicy();

                CborReader reader;
                var allHeaders = msg.ProtectedHeaders.Union(msg.UnprotectedHeaders);
                foreach ((CoseHeaderLabel label, ReadOnlyMemory<byte> encodedValue) in allHeaders)
                {
                    reader = new CborReader(encodedValue);

                    if (label == Labels.labelx5t)
                    {
                        thumbprint = CoseX509Thumprint.Deserialize(reader);
                    }
                    else if (label == Labels.labelx5chain)
                    {
                        if (!reader.TryReadCertificateSet(ref chainCerts, out CoseX509FormatException ex))
                        {
                            throw new CoseX509FormatException("Failed to read certs from x5chain header", ex);
                        }
                    }
                    else if (label == Labels.labelx5bag)
                    {
                        if (!reader.TryReadCertificateSet(ref extraCerts, out CoseX509FormatException ex))
                        {
                            throw new CoseX509FormatException("Failed to read certs from x5bag header", ex);
                        }
                    }
                }

                if (thumbprint is not null)
                {
                    signingCert = chainCerts.Union(extraCerts).FirstOrDefault(thumbprint.Match);
                }

                if (signingCert is not null)
                {
                    policy.ExtraStore.AddRange(extraCerts);
                    using var chain = new X509Chain() { ChainPolicy = policy };
                    if (chain.Build(signingCert))
                    {
                        return true;
                    }
                }
            }
            finally
            {
                // X509Certificate2Collections are not disposible
                extraCerts.Clear();
                chainCerts.Clear();
            }

            return false;
        }
        #endregion

        #region X509Certificate2 extensions
        /// <summary>
        /// Builds the certificate chain for the current certificate as a leaf node, based on its known trust relationships.
        /// </summary>
        /// <param name="leafCert">The current certificate as a leaf node.</param>
        /// <returns>The completed chain.</returns>
        /// <exception cref="CoseSigningException">The chain could not be built.</exception>
        public static X509Chain GetChain(this X509Certificate2 leafCert)
        {
            X509Chain certChain = new();
            certChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            certChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;

            // Add the signing cert in case its a self signed chain
            certChain.ChainPolicy.CustomTrustStore.Add(leafCert);
            if (false == certChain.Build(leafCert))
            {
                throw new CoseSigningException($"Failed to build certificate chain for cert {leafCert.Thumbprint}");
            }

            return certChain;
        }

        /// <summary>
        /// Validates that the Common Name provided matches the common name of the certificate.
        /// </summary>
        /// <param name="cert">The certificate to check.</param>
        /// <param name="commonName">The certificate Common Name to require.</param>
        /// <exception cref="CoseValidationExecption">The certificate did not match the required Common Name.</exception>
        /// <remarks>The match performed by ValidateCommonName is case-sensitive.</remarks>
        public static void ValidateCommonName(this X509Certificate2 cert, string? commonName)
        {
            if (commonName is not null)
            {
                string signingCertSubjectName = cert.SubjectName.Format(multiLine: false);

                if (!commonName.Equals(signingCertSubjectName, StringComparison.Ordinal))
                {
                    throw new CoseValidationException($"Signing certificate common name [{signingCertSubjectName}] does not match required name [{commonName}]");
                }
            }
        }
        #endregion

        #region CborReader extensions
        /// <summary>
        /// Tries to load a collection of certificates into the current CborReader.
        /// </summary>
        /// <param name="reader">The current CborReader.</param>
        /// <param name="certificates">The certificates to read.</param>
        /// <param name="ex">The exception thrown on failure, if any.</param>
        /// <returns>True on success; false otherwise.</returns>
        public static bool TryReadCertificateSet(this CborReader reader, ref X509Certificate2Collection certificates, out CoseX509FormatException ex)
        {
            ex = null;
            try
            {
                reader.ReadCertificateSet(ref certificates);
            }
            catch (CoseX509FormatException e)
            {
                ex = e;
                return false;
            }
            return true;
        }

        /// <summary>
        /// Loads a collection of certificates into the current CborReader.
        /// </summary>
        /// <param name="reader">The current CborReader.</param>
        /// <param name="certificates">The certificates to read.</param>
        /// <exception cref="CoseX509FormatException">The certificate collection was not in a valid CBOR-supported format.</exception>
        public static void ReadCertificateSet(this CborReader reader, ref X509Certificate2Collection certificates)
        {
            if (reader.PeekState() == CborReaderState.ByteString)
            {
                var certBytes = reader.ReadByteString();
                if (certBytes.Length > 0)
                {
                    certificates.Add(new X509Certificate2(certBytes));
                }
            }
            else if (reader.PeekState() == CborReaderState.StartArray)
            {
                var certCount = reader.ReadStartArray();
                for (int i = 0; i < certCount; i++)
                {
                    if (reader.PeekState() != CborReaderState.ByteString)
                    {
                        throw new CoseX509FormatException("Certificate array must only contain ByteString");
                    }
                    var certBytes = reader.ReadByteString();
                    if (certBytes.Length > 0)
                    {
                        certificates.Add(new X509Certificate2(certBytes));
                    }
                }
                reader.ReadEndArray();
            }
            else
            {
                throw new CoseX509FormatException("Certificate collections must be ByteString for single certificate or Array for multiple certificates");
            }
        }
        #endregion

        #region CborWriter extensions
        internal static void EncodeCertList(this CborWriter writer, IEnumerable<X509Certificate2> certs)
        {
            //Reset the writer so it only contains the proper data at the end of this function
            writer.Reset();

            if (certs.Any())
            {
                int certCount = certs.Count();
                if (certCount != 1)
                {
                    writer.WriteStartArray(certs.Count());
                }
                foreach (var cert in certs)
                {
                    writer.WriteByteString(cert.GetRawCertData());
                }
                if (certCount != 1)
                {
                    writer.WriteEndArray();
                }
            }
            else
            {
                writer.WriteByteString(Array.Empty<byte>());
            }
        }
        #endregion
    }
}
