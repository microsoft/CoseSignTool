// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Security.Cryptography.X509Certificates;

namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Extensions for the <see cref="CborWriter"/> class.
/// </summary>
public static class CborWriterExtensions
{
    /// <summary>
    /// Encodes a certificate list into the <see cref="CborWriter"/> object.
    /// </summary>
    /// <param name="writer">The <see cref="CborWriter"/> to encode the certificates into.</param>
    /// <param name="certs">The list of certificates to be encoded.</param>
    public static void EncodeCertList(this CborWriter writer, IEnumerable<X509Certificate2> certs)
    {
        if (writer == null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        if (certs == null)
        {
            throw new ArgumentNullException(nameof(certs));
        }

        writer.Reset();

        int certCount = certs.Count();

        switch (certCount)
        {
            case 0:
                writer.WriteByteString(Array.Empty<byte>());
                break;

            case 1:
                writer.WriteByteString(certs.First().RawData);
                break;

            default:
                writer.WriteStartArray(certCount);
                foreach (var cert in certs)
                {
                    writer.WriteByteString(cert.RawData);
                }
                writer.WriteEndArray();
                break;
        }
    }
}
