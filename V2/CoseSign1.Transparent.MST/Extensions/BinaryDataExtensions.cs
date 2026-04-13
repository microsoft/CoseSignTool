// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Extensions;

using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;

/// <summary>
/// Extension methods for <see cref="BinaryData"/> to work with MST responses.
/// </summary>
[ExcludeFromCodeCoverage]
public static class BinaryDataExtensions
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string EntryIdKey = "EntryId";
        public const string CborMapExceedsMaxEntryCountPrefix = "CBOR map exceeds maximum entry count of ";
    }

    /// <summary>
    /// Attempts to extract the "EntryId" value from CBOR-encoded MST response data.
    /// </summary>
    /// <param name="binaryData">The CBOR-encoded binary data from MST.</param>
    /// <param name="entryId">The extracted entry ID, or null if extraction failed.</param>
    /// <returns>True if the entry ID was successfully extracted; otherwise, false.</returns>
    /// <exception cref="CborContentException">Thrown when the CBOR map exceeds the maximum entry count.</exception>
    public static bool TryGetMstEntryId(this BinaryData binaryData, out string? entryId)
    {
        entryId = null;

        if (binaryData == null)
        {
            return false;
        }

        try
        {
            CborReader cborReader = new(binaryData);
            cborReader.ReadStartMap();
            const int MaxMapEntries = 256;
            int mapEntryCount = 0;
            while (cborReader.PeekState() != CborReaderState.EndMap)
            {
                if (++mapEntryCount > MaxMapEntries)
                {
                    throw new CborContentException(string.Concat(ClassStrings.CborMapExceedsMaxEntryCountPrefix, MaxMapEntries.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                }

                string key = cborReader.ReadTextString();
                if (key == ClassStrings.EntryIdKey)
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
        catch (InvalidOperationException)
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