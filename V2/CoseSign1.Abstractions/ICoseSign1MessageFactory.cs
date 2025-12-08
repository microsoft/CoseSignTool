using System;
using System.IO;
using System.Security.Cryptography.Cose;
using System.Threading;
using System.Threading.Tasks;

namespace CoseSign1.Abstractions;

/// <summary>
/// Factory interface for creating COSE Sign1 messages with configurable signing options.
/// </summary>
/// <typeparam name="TOptions">The type of signing options, which must derive from <see cref="SigningOptions"/>.</typeparam>
public interface ICoseSign1MessageFactory<TOptions> : IDisposable
    where TOptions : SigningOptions
{
    /// <summary>
    /// Creates a COSE Sign1 message from a byte array payload and returns it as bytes.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    byte[] CreateCoseSign1MessageBytes(
        byte[] payload,
        string contentType,
        TOptions? options = default);

    /// <summary>
    /// Creates a COSE Sign1 message from a ReadOnlySpan payload and returns it as bytes.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    byte[] CreateCoseSign1MessageBytes(
        ReadOnlySpan<byte> payload,
        string contentType,
        TOptions? options = default);

    /// <summary>
    /// Creates a COSE Sign1 message from a byte array payload and returns it as bytes.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    Task<byte[]> CreateCoseSign1MessageBytesAsync(
        byte[] payload,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a COSE Sign1 message from a ReadOnlyMemory payload and returns it as bytes.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    Task<byte[]> CreateCoseSign1MessageBytesAsync(
        ReadOnlyMemory<byte> payload,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a COSE Sign1 message from a stream payload and returns it as bytes.
    /// </summary>
    /// <param name="payloadStream">The payload stream to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/octet-stream").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message as a byte array.</returns>
    Task<byte[]> CreateCoseSign1MessageBytesAsync(
        Stream payloadStream,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a COSE Sign1 message from a byte array payload.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <returns>The COSE Sign1 message.</returns>
    CoseSign1Message CreateCoseSign1Message(
        byte[] payload,
        string contentType,
        TOptions? options = default);

    /// <summary>
    /// Creates a COSE Sign1 message from a ReadOnlySpan payload.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <returns>The COSE Sign1 message.</returns>
    CoseSign1Message CreateCoseSign1Message(
        ReadOnlySpan<byte> payload,
        string contentType,
        TOptions? options = default);

    /// <summary>
    /// Creates a COSE Sign1 message from a byte array payload.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message.</returns>
    Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        byte[] payload,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a COSE Sign1 message from a ReadOnlyMemory payload.
    /// </summary>
    /// <param name="payload">The payload to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/json").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message.</returns>
    Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        ReadOnlyMemory<byte> payload,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a COSE Sign1 message from a stream payload.
    /// </summary>
    /// <param name="payloadStream">The payload stream to sign.</param>
    /// <param name="contentType">The content type of the payload (e.g., "application/octet-stream").</param>
    /// <param name="options">Optional signing options. If null, default options are used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The COSE Sign1 message.</returns>
    Task<CoseSign1Message> CreateCoseSign1MessageAsync(
        Stream payloadStream,
        string contentType,
        TOptions? options = default,
        CancellationToken cancellationToken = default);
}
