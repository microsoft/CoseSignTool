// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Configuration;

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Security.Cryptography;

/// <summary>
/// Provides information about the running application including version and binary hash.
/// </summary>
public static class ApplicationInfo
{
    private static string? _cachedBinaryHash;
    private static readonly object HashLock = new();

    /// <summary>
    /// String constants specific to this class.
    /// </summary>
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string AppName = "CoseSignTool";
        public const string BannerSeparator = "================================================================================";
        public const string BannerFormat = """
            {0}
            {1}
              Version:     {2}
              File:        {3}
              SHA256:      {4}
              .NET:        {5}
              Timestamp:   {6:O}
            {0}
            """;
        public const string UnknownVersion = "0.0.0";
        public const string UnknownHash = "<unavailable>";
        public const string UnknownPath = "<unknown>";
    }

    /// <summary>
    /// Gets the application name.
    /// </summary>
    public static string Name => ClassStrings.AppName;

    /// <summary>
    /// Gets the application version from the assembly's informational version attribute,
    /// falling back to file version, then assembly version.
    /// </summary>
    public static string Version
    {
        get
        {
            var assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();

            // Try informational version first (includes git hash, etc.)
            var infoVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            if (!string.IsNullOrEmpty(infoVersion))
            {
                return infoVersion;
            }

            // Try file version next
            var fileVersionInfo = FileVersionInfo.GetVersionInfo(assembly.Location);
            if (!string.IsNullOrEmpty(fileVersionInfo.FileVersion))
            {
                return fileVersionInfo.FileVersion;
            }

            // Fall back to assembly version
            return assembly.GetName().Version?.ToString() ?? ClassStrings.UnknownVersion;
        }
    }

    /// <summary>
    /// Gets the path to the executing binary.
    /// </summary>
    public static string ExecutablePath
    {
        get
        {
            try
            {
                var assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
                return assembly.Location;
            }
            catch
            {
                return ClassStrings.UnknownPath;
            }
        }
    }

    /// <summary>
    /// Gets the SHA256 hash of the executing binary.
    /// The hash is cached after first computation.
    /// </summary>
    public static string BinaryHash
    {
        get
        {
            if (_cachedBinaryHash != null)
            {
                return _cachedBinaryHash;
            }

            lock (HashLock)
            {
                // Double-check after acquiring lock
                if (_cachedBinaryHash != null)
                {
                    return _cachedBinaryHash;
                }

                _cachedBinaryHash = ComputeBinaryHash();
                return _cachedBinaryHash;
            }
        }
    }

    /// <summary>
    /// Gets the .NET runtime version.
    /// </summary>
    public static string RuntimeVersion => Environment.Version.ToString();

    /// <summary>
    /// Generates a formatted banner string with application information.
    /// </summary>
    /// <returns>A multi-line banner string suitable for logging.</returns>
    public static string GetBanner()
    {
        return string.Format(
            ClassStrings.BannerFormat,
            ClassStrings.BannerSeparator,
            Name,
            Version,
            ExecutablePath,
            BinaryHash,
            RuntimeVersion,
            DateTimeOffset.UtcNow);
    }

    private static string ComputeBinaryHash()
    {
        try
        {
            var path = ExecutablePath;
            if (string.IsNullOrEmpty(path) || path == ClassStrings.UnknownPath || !File.Exists(path))
            {
                return ClassStrings.UnknownHash;
            }

            using var stream = File.OpenRead(path);
            var hash = SHA256.HashData(stream);
            return Convert.ToHexString(hash);
        }
        catch
        {
            return ClassStrings.UnknownHash;
        }
    }

    /// <summary>
    /// Resets the cached binary hash. Intended for testing only.
    /// </summary>
    internal static void ResetCache()
    {
        lock (HashLock)
        {
            _cachedBinaryHash = null;
        }
    }
}
