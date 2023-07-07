// ---------------------------------------------------------------------------
// <copyright file="ObjectExtensions.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseX509;

/// <summary>
/// Extension methods for <see cref="object"/>.
/// </summary>
public static class ObjectExtensions
{
    /// <summary>
    /// Returns true if the array is null or empty.
    /// </summary>
    /// <param name="a">The current array of objects.</param>
    /// <returns>True if the array is null or empty; false otherwise.</returns>
    public static bool IsNullOrEmpty<T>([NotNullWhen(false)] this T[]? a) =>
        a is null || a.Length == 0;

    /// <summary>
    /// Returns true if the array is null or empty.
    /// </summary>
    /// <param name="a">The current array of objects.</param>
    /// <returns>True if the array is null or empty; false otherwise.</returns>
    public static bool IsNullOrEmpty<T>([NotNullWhen(false)] this List<T> a) =>
        a is null || a.Count == 0;
}
