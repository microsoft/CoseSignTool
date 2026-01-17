// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Subjects;

using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using CoseSign1.Abstractions;

/// <summary>
/// A stable, content-addressed identifier for a trust subject.
/// </summary>
/// <remarks>
/// This is typically derived from SHA-256 of canonical bytes for the subject.
/// </remarks>
public readonly struct TrustSubjectId : IEquatable<TrustSubjectId>
{
    private const int Sha256DigestLength = 32;

    private readonly byte[]? BytesValue;

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorExpectedSha256Length = "Expected 32 bytes";
        public const string ErrorUninitialized = "TrustSubjectId is uninitialized (default value)";
        public const string HexChars = "0123456789abcdef";
    }

    private TrustSubjectId(byte[] sha256Bytes)
    {
        Guard.ThrowIfNull(sha256Bytes);

        if (sha256Bytes.Length != Sha256DigestLength)
        {
            throw new ArgumentException(ClassStrings.ErrorExpectedSha256Length, nameof(sha256Bytes));
        }

        BytesValue = sha256Bytes;
    }

    /// <summary>
    /// Gets the raw SHA-256 digest bytes.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if the value is uninitialized (default).</exception>
    public ReadOnlySpan<byte> Bytes => BytesValue ?? throw new InvalidOperationException(ClassStrings.ErrorUninitialized);

    /// <summary>
    /// Gets a lowercase hex representation of the ID.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if the value is uninitialized (default).</exception>
    public string Hex => ToLowerHex(Bytes);

    /// <summary>
    /// Creates a subject ID from the SHA-256 of the provided bytes.
    /// </summary>
    /// <param name="data">The bytes to hash.</param>
    /// <returns>The resulting subject ID.</returns>
    public static TrustSubjectId FromSha256OfBytes(ReadOnlySpan<byte> data)
    {
        return new TrustSubjectId(ComputeSha256(data));
    }

    /// <inheritdoc />
    public override string ToString() => Hex;

    /// <inheritdoc />
    public bool Equals(TrustSubjectId other)
    {
        if (BytesValue == null || other.BytesValue == null)
        {
            return BytesValue == other.BytesValue;
        }

        return FixedTimeEquals(BytesValue, other.BytesValue);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj)
    {
        return obj is TrustSubjectId other && Equals(other);
    }

    /// <inheritdoc />
    public override int GetHashCode()
    {
        if (BytesValue == null)
        {
            return 0;
        }

        // Use 16 bytes to reduce collisions while staying cheap.
        var span = BytesValue.AsSpan();
        unchecked
        {
            int hash = 17;
            hash = (hash * 31) + BinaryPrimitives.ReadInt32LittleEndian(span.Slice(0, 4));
            hash = (hash * 31) + BinaryPrimitives.ReadInt32LittleEndian(span.Slice(4, 4));
            hash = (hash * 31) + BinaryPrimitives.ReadInt32LittleEndian(span.Slice(8, 4));
            hash = (hash * 31) + BinaryPrimitives.ReadInt32LittleEndian(span.Slice(12, 4));
            return hash;
        }
    }

    private static byte[] ComputeSha256(ReadOnlySpan<byte> data)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data.ToArray());
    }

    private static bool FixedTimeEquals(byte[] left, byte[] right)
    {
        Guard.ThrowIfNull(left);
        Guard.ThrowIfNull(right);

        if (left.Length != right.Length)
        {
            return false;
        }

        int diff = 0;
        for (int i = 0; i < left.Length; i++)
        {
            diff |= left[i] ^ right[i];
        }

        return diff == 0;
    }

    private static string ToLowerHex(ReadOnlySpan<byte> bytes)
    {
        char[] chars = new char[bytes.Length * 2];
        int idx = 0;
        foreach (byte b in bytes)
        {
            chars[idx++] = ClassStrings.HexChars[b >> 4];
            chars[idx++] = ClassStrings.HexChars[b & 0x0F];
        }

        return new string(chars);
    }

    /// <summary>
    /// Returns a value indicating whether two subject IDs are equal.
    /// </summary>
    /// <param name="left">The first ID.</param>
    /// <param name="right">The second ID.</param>
    /// <returns><see langword="true"/> if the IDs are equal; otherwise <see langword="false"/>.</returns>
    public static bool operator ==(TrustSubjectId left, TrustSubjectId right) => left.Equals(right);

    /// <summary>
    /// Returns a value indicating whether two subject IDs are not equal.
    /// </summary>
    /// <param name="left">The first ID.</param>
    /// <param name="right">The second ID.</param>
    /// <returns><see langword="true"/> if the IDs are not equal; otherwise <see langword="false"/>.</returns>
    public static bool operator !=(TrustSubjectId left, TrustSubjectId right) => !left.Equals(right);
}
