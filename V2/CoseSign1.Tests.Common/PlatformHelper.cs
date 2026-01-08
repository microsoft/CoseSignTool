// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using NUnit.Framework;

namespace CoseSign1.Tests.Common;

/// <summary>
/// Provides platform detection and test skipping utilities.
/// </summary>
public static class PlatformHelper
{
    internal static class ClassStrings
    {
        public const string PlatformWindows = "Windows";
        public const string PlatformLinux = "Linux";
        public const string PlatformMacOS = "macOS";
        public const string PlatformOther = "this platform";

        public const string DefaultFeature = "This feature";

        public const string ErrorMldsaNotSupportedFormat = "ML-DSA (post-quantum cryptography) is not supported on {0}. This test requires Windows.";
        public const string ErrorWindowsOnlyFormat = "{0} is only supported on Windows. Current platform: {1}";
        public const string ErrorLinuxOnlyFormat = "{0} is only supported on Linux. Current platform: {1}";
    }

    /// <summary>
    /// Gets a value indicating whether the current platform is Windows.
    /// </summary>
    public static bool IsWindows => OperatingSystem.IsWindows();

    /// <summary>
    /// Gets a value indicating whether the current platform is Linux.
    /// </summary>
    public static bool IsLinux => OperatingSystem.IsLinux();

    /// <summary>
    /// Gets a value indicating whether the current platform is macOS.
    /// </summary>
    public static bool IsMacOS => OperatingSystem.IsMacOS();

    /// <summary>
    /// Gets a value indicating whether ML-DSA (post-quantum cryptography) is supported on the current platform.
    /// Currently, ML-DSA is only supported on Windows in .NET 10 preview.
    /// </summary>
    public static bool IsMLDsaSupported => IsWindows;

    /// <summary>
    /// Skips the current test if ML-DSA is not supported on the current platform.
    /// Call this at the beginning of any test that requires ML-DSA functionality.
    /// </summary>
    /// <param name="reason">Optional custom reason message.</param>
    public static void SkipIfMLDsaNotSupported(string? reason = null)
    {
        if (!IsMLDsaSupported)
        {
            var platform = IsLinux ? ClassStrings.PlatformLinux : IsMacOS ? ClassStrings.PlatformMacOS : ClassStrings.PlatformOther;
            var message = reason ?? string.Format(ClassStrings.ErrorMldsaNotSupportedFormat, platform);
            Assert.Inconclusive(message);
        }
    }

    /// <summary>
    /// Skips the current test if not running on Windows.
    /// </summary>
    /// <param name="feature">The feature that requires Windows.</param>
    public static void SkipIfNotWindows(string feature = ClassStrings.DefaultFeature)
    {
        if (!IsWindows)
        {
            var platform = IsLinux ? ClassStrings.PlatformLinux : IsMacOS ? ClassStrings.PlatformMacOS : ClassStrings.PlatformOther;
            Assert.Inconclusive(string.Format(ClassStrings.ErrorWindowsOnlyFormat, feature, platform));
        }
    }

    /// <summary>
    /// Skips the current test if not running on Linux.
    /// </summary>
    /// <param name="feature">The feature that requires Linux.</param>
    public static void SkipIfNotLinux(string feature = ClassStrings.DefaultFeature)
    {
        if (!IsLinux)
        {
            var platform = IsWindows ? ClassStrings.PlatformWindows : IsMacOS ? ClassStrings.PlatformMacOS : ClassStrings.PlatformOther;
            Assert.Inconclusive(string.Format(ClassStrings.ErrorLinuxOnlyFormat, feature, platform));
        }
    }
}
