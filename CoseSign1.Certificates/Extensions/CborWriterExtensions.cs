// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Extensions for the <see cref="CborWriter"/> class.
/// </summary>
public static class CborWriterExtensions
{
    /// <summary>
    /// Encodes a given certificate list into the <see cref="CborWriter"/> object.
    /// </summary>
    /// <param name="writer">The <see cref="CborWriter"/> to encode the certificates into.</param>
    /// <param name="certs">The <see cref="IEnumerable{X509Certificate2}"/> list of certificates to be encoded to the <paramref name="writer"/> object.</param>
    public static void EncodeCertList(this CborWriter writer, IEnumerable<X509Certificate2> certs)
    {
        // Reset the writer so it only contains the proper data at the end of this function
        writer.Reset();

        // Get the cert count here so we only have to calculate it once
        int certCount = certs.Count();

        // Write the certs to an array. If there's just one we can skip the start and end delimiters.
        switch (certCount)
        {
            case 0:
                writer.WriteByteString(Array.Empty<byte>());
                break;

            case 1:
                writer.WriteByteString(certs.FirstOrDefault().GetRawCertData());
                break;

            default:
                writer.WriteStartArray(certCount);
                foreach (X509Certificate2 cert in certs)
                {
                    writer.WriteByteString(cert.GetRawCertData());
                }
                writer.WriteEndArray();
                break;
        }
    }
}
