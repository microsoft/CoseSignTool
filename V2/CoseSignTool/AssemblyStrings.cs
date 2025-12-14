// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool;

/// <summary>
/// Internal static strings shared across multiple classes within the CoseSignTool assembly.
/// For strings unique to a single class, use a private static ClassStrings nested class instead.
/// </summary>
internal static class AssemblyStrings
{
    /// <summary>
    /// Common I/O indicators used across multiple handlers.
    /// </summary>
    internal static class IO
    {
        internal static readonly string StdinIndicator = "-";
        internal static readonly string StdinDisplayName = "<stdin>";
        internal static readonly string StdoutDisplayName = "<stdout>";
        internal static readonly string CoseFileExtension = ".cose";
    }

    /// <summary>
    /// Common display values used across formatters and handlers.
    /// </summary>
    internal static class Display
    {
        internal static readonly string Embedded = "Embedded";
        internal static readonly string Detached = "Detached";
        internal static readonly string Yes = "Yes";
        internal static readonly string No = "No";
    }

    /// <summary>
    /// Common error message templates used across multiple classes.
    /// </summary>
    internal static class Errors
    {
        internal static readonly string FileNotFound = "File not found: {0}";
        internal static readonly string NoStdinData = "No signature data received from stdin";
        internal static readonly string StdinTimeout = "No signature data received from stdin (timed out after {0:F0}s)";
    }

    /// <summary>
    /// Format strings used across multiple classes.
    /// </summary>
    internal static class Formats
    {
        internal static readonly string ByteCount = "{0:N0} bytes";
        internal static readonly string DateTimeUtc = "yyyy-MM-dd HH:mm:ss UTC";
    }
}
