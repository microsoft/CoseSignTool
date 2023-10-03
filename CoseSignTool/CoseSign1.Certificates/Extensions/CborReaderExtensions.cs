// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Extensions for the <see cref="CborReader"/> class.
/// </summary>
public static class CborReaderExtensions
{
    /// <summary>
    /// Tries to load a collection of certificates into the current CborReader.
    /// </summary>
    /// <param name="reader">The current CborReader.</param>
    /// <param name="certificates">The certificates to read.</param>
    /// <param name="ex">The exception thrown on failure, if any.</param>
    /// <returns>True on success; false otherwise.</returns>
    public static bool TryReadCertificateSet(
        this CborReader reader,
        ref List<X509Certificate2> certificates,
        out CoseX509FormatException? ex)
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
    public static void ReadCertificateSet(this CborReader reader, ref List<X509Certificate2> certificates)
    {
        CborReaderState peekState = reader.PeekState();
        if (peekState == CborReaderState.ByteString)
        {
            byte[] certBytes = reader.ReadByteString();
            if (certBytes.Length > 0)
            {
                certificates.Add(new X509Certificate2(certBytes));
            }
        }
        else if (peekState == CborReaderState.StartArray)
        {
            int? certCount = reader.ReadStartArray();
            for (int i = 0; i < certCount; i++)
            {
                if (reader.PeekState() != CborReaderState.ByteString)
                {
                    throw new CoseX509FormatException("Certificate array must only contain ByteString");
                }
                byte[] certBytes = reader.ReadByteString();
                if (certBytes.Length > 0)
                {
                    certificates.Add(new X509Certificate2(certBytes));
                }
            }
            reader.ReadEndArray();
        }
        else
        {
            throw new CoseX509FormatException(
                "Certificate collections must be ByteString for single certificate or Array for multiple certificates");
        }
    }
}
