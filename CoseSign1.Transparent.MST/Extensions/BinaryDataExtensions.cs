// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Extensions;

using System;
using System.Formats.Cbor;
using Azure;

/// <summary>
/// Provides extension methods for working with <see cref="Response{BinaryData}"/> objects,
/// specifically for extracting information from CBOR-encoded data.
/// </summary>
public static class BinaryDataExtensions
{
    /// <summary>
    /// Attempts to extract the "EntryId" value from the CBOR-encoded content of a <see cref="BinaryData"/>.
    /// </summary>
    /// <param name="binaryData">The <see cref="BinaryData"/> containing the CBOR-encoded data.</param>
    /// <param name="entryId">
    /// When this method returns, contains the extracted "EntryId" value if the operation was successful;
    /// otherwise, contains <c>null</c>.
    /// </param>
    /// <returns>
    /// <c>true</c> if the "EntryId" was successfully extracted; otherwise, <c>false</c>.
    /// </returns>
    /// <remarks>
    /// This method reads the CBOR-encoded data as a map and searches for a key named "EntryId".
    /// If the key is found, its corresponding value is returned as a string.
    /// If the data is not valid CBOR or does not contain the "EntryId" key, the method returns <c>false</c>.
    /// </remarks>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="binaryData"/> is <c>null</c>.</exception>
    public static bool TryGetMstEntryId(this BinaryData binaryData, out string? entryId)
    {
        entryId = string.Empty;

        if (binaryData == null)
        {
            return false;
        }

        try
        {
            CborReader cborReader = new(binaryData);
            cborReader.ReadStartMap();
            while (cborReader.PeekState() != CborReaderState.EndMap)
            {
                string key = cborReader.ReadTextString();
                if (key == "EntryId")
                {
                    entryId = cborReader.ReadTextString();
                    return true;
                }
                else
                {
                    cborReader.SkipValue();
                }
            }
        }
        catch(InvalidOperationException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (CborContentException)
        {
            return false;
        }

        return false;
    }
}

