// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;

namespace CoseSign1.Transparent.MST.Extensions;

/// <summary>
/// Extension methods for <see cref="BinaryData"/> to work with MST responses.
/// </summary>
public static class BinaryDataExtensions
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string EntryIdKey = "EntryId";
    }

    /// <summary>
    /// Attempts to extract the "EntryId" value from CBOR-encoded MST response data.
    /// </summary>
    /// <param name="binaryData">The CBOR-encoded binary data from MST.</param>
    /// <param name="entryId">The extracted entry ID, or null if extraction failed.</param>
    /// <returns>True if the entry ID was successfully extracted; otherwise, false.</returns>
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
            while (cborReader.PeekState() != CborReaderState.EndMap)
            {
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