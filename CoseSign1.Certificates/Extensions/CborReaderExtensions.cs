// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Extensions;

using System.Diagnostics;

/// <summary>
/// Extensions for the <see cref="CborReader"/> class.
/// </summary>
/// <remarks>
/// Logging is done through Trace.TraceError and Debug.WriteLine.
/// </remarks>
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
        if (reader == null)
        {
            throw new ArgumentNullException(nameof(reader));
        }

        if(certificates == null)
        {
            throw new ArgumentNullException(nameof(certificates));
        }


        ex = null;
        try
        {
            reader.ReadCertificateSet(ref certificates);
        }
        catch (CoseX509FormatException e)
        {
            ex = e;
            Trace.TraceWarning($"Encountered exception: {e} in {nameof(ReadCertificateSet)}, returning false.");
            return false;
        }
        return true;
    }

    /// <summary>
    /// Loads a collection of certificates into the current CborReader.
    /// </summary>
    /// <param name="reader">The current CborReader.</param>
    /// <param name="certificates">The list of certificates to load with certificates from this certificate set.</param>
    /// <exception cref="CoseX509FormatException">The certificate collection was not in a valid CBOR-supported format.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="reader"/> or <paramref name="certificates"/> is null.</exception>
    public static void ReadCertificateSet(this CborReader reader, ref List<X509Certificate2> certificates)
    {
        if (reader == null)
        {
            throw new ArgumentNullException(nameof(reader));
        }

        if (certificates == null)
        {
            throw new ArgumentNullException(nameof(certificates));
        }

        try
        {
            CborReaderState peekState = reader.PeekState();
            if (peekState == CborReaderState.ByteString)
            {
                try
                {
                    certificates.Add(reader.ReadByteStringAsCertificate());
                }
                catch(CoseX509FormatException ex)
                {
                    Trace.TraceWarning($"Failed to read certificates from CborReader: {reader.GetHashCode()} with exception: {ex}, unable to read certificate set.");
                }
            }
            else if (peekState == CborReaderState.StartArray)
            {
                int? certCount = reader.ReadStartArray();
                for (int i = 0; i < certCount; i++)
                {
                    certificates.Add(reader.ReadByteStringAsCertificate());
                }
                reader.ReadEndArray();
            }
            else
            {
                throw new CoseX509FormatException(
                    "Certificate collections must be ByteString for single certificate or Array for multiple certificates");
            }
        }
        catch(Exception ex) when (ex is not CoseX509FormatException)
        {
            throw new CoseX509FormatException(ex.Message, ex);
        }
    }

    /// <summary>
    /// Extracts a certificate from the ByteString on this <see cref="CborReader"/>.
    /// </summary>
    /// <param name="reader">The <see cref="CborReader"/> to extract a certificate from presuming it's on a ByteString.</param>
    /// <returns>A <see cref="X509Certificate2"/> extracted from the ByteString.</returns>
    /// <exception cref="CoseX509FormatException">Thrown if the <paramref name="reader"/> is not on a ByteString, or if the extract ByteString cannot be converted into a <see cref="X509Certificate2"/>.</exception>
    private static X509Certificate2 ReadByteStringAsCertificate(this CborReader reader)
    {
        if (reader.PeekState() != CborReaderState.ByteString)
        {
            throw new CoseX509FormatException($"Certificate array must only contain ByteString on reader: {reader.GetHashCode()}");
        }
        byte[] certBytes = reader.ReadByteString();

        return certBytes.Length > 0
            ? new X509Certificate2(certBytes)
            : throw new CoseX509FormatException($"Failed to read certificate bytes from ByteString on CborReader: {reader.GetHashCode()} and convert to a certificate.");
    }
}
