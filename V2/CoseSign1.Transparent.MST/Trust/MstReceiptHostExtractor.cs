// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using System.Text;
using System.Text.RegularExpressions;

internal static partial class MstReceiptHostExtractor
{
    internal static class ClassStrings
    {
        public const string HostnameRegexPattern = "(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}";
    }

    internal static IReadOnlyList<string> ExtractHostCandidates(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0)
        {
            return Array.Empty<string>();
        }

        const int minTokenLength = 4;
        var asciiBuilder = new StringBuilder(capacity: Math.Min(bytes.Length, 4096));
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        static void ProcessChunk(string chunk, HashSet<string> found)
        {
            if (chunk.Length < minTokenLength)
            {
                return;
            }

            foreach (Match match in Regex.Matches(chunk, ClassStrings.HostnameRegexPattern))
            {
                var host = match.Value;
                if (!string.IsNullOrWhiteSpace(host))
                {
                    found.Add(host);
                }
            }
        }

        for (var i = 0; i < bytes.Length; i++)
        {
            var b = bytes[i];
            if (b >= 0x20 && b <= 0x7E)
            {
                asciiBuilder.Append((char)b);
                continue;
            }

            if (asciiBuilder.Length > 0)
            {
                ProcessChunk(asciiBuilder.ToString(), found);
                asciiBuilder.Clear();
            }
        }

        if (asciiBuilder.Length > 0)
        {
            ProcessChunk(asciiBuilder.ToString(), found);
        }

        return found.Count == 0 ? Array.Empty<string>() : found.ToArray();
    }
}
