// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using NUnit.Framework;

namespace CoseSign1.Tests.Common;

/// <summary>
/// Provides platform detection and test skipping utilities.
/// </summary>
public static class PlatformHelper
{
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
            var platform = IsLinux ? "Linux" : IsMacOS ? "macOS" : "this platform";
            var message = reason ?? $"ML-DSA (post-quantum cryptography) is not supported on {platform}. This test requires Windows.";
            Assert.Inconclusive(message);
        }
    }

    /// <summary>
    /// Skips the current test if not running on Windows.
    /// </summary>
    /// <param name="feature">The feature that requires Windows.</param>
    public static void SkipIfNotWindows(string feature = "This feature")
    {
        if (!IsWindows)
        {
            var platform = IsLinux ? "Linux" : IsMacOS ? "macOS" : "this platform";
            Assert.Inconclusive($"{feature} is only supported on Windows. Current platform: {platform}");
        }
    }

    /// <summary>
    /// Skips the current test if not running on Linux.
    /// </summary>
    /// <param name="feature">The feature that requires Linux.</param>
    public static void SkipIfNotLinux(string feature = "This feature")
    {
        if (!IsLinux)
        {
            var platform = IsWindows ? "Windows" : IsMacOS ? "macOS" : "this platform";
            Assert.Inconclusive($"{feature} is only supported on Linux. Current platform: {platform}");
        }
    }
}
