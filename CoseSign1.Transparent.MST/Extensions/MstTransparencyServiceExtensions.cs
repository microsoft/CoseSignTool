// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Extensions;

using System;
using Azure.Security.CodeTransparency;
using CoseSign1.Transparent;

/// <summary>
/// Provides extension methods for working with the <see cref="CodeTransparencyClient"/> 
/// to integrate it with the <see cref="TransparencyService"/> base class.
/// </summary>
public static class MstTransparencyServiceExtensions
{
    /// <summary>
    /// Converts a <see cref="CodeTransparencyClient"/> instance into a <see cref="TransparencyService"/> implementation.
    /// </summary>
    /// <param name="client">The <see cref="CodeTransparencyClient"/> to be converted.</param>
    /// <returns>
    /// An instance of <see cref="TransparencyService"/> that wraps the provided <see cref="CodeTransparencyClient"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="client"/> is <c>null</c>.</exception>
    /// <remarks>
    /// This extension method simplifies the integration of the Azure Code Transparency Service (CTS) 
    /// with the <see cref="TransparencyService"/> base class, enabling seamless usage of CTS 
    /// within the CoseSign1 transparency ecosystem.
    /// </remarks>
    public static TransparencyService ToCoseSign1TransparencyService(this CodeTransparencyClient client)
    {
        if (client == null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        return new MstTransparencyService(client);
    }

    /// <summary>
    /// Converts a <see cref="CodeTransparencyClient"/> instance into a <see cref="TransparencyService"/> implementation with logging support.
    /// </summary>
    /// <param name="client">The <see cref="CodeTransparencyClient"/> to be converted.</param>
    /// <param name="logVerbose">Optional callback for verbose logging.</param>
    /// <param name="logWarning">Optional callback for warning logging.</param>
    /// <param name="logError">Optional callback for error logging.</param>
    /// <returns>
    /// An instance of <see cref="TransparencyService"/> that wraps the provided <see cref="CodeTransparencyClient"/> with logging enabled.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="client"/> is <c>null</c>.</exception>
    /// <remarks>
    /// This extension method enables logging integration for transparency operations, allowing
    /// diagnostic output during registration and verification processes.
    /// </remarks>
    public static TransparencyService ToCoseSign1TransparencyService(
        this CodeTransparencyClient client,
        Action<string>? logVerbose = null,
        Action<string>? logWarning = null,
        Action<string>? logError = null)
    {
        if (client == null)
        {
            throw new ArgumentNullException(nameof(client));
        }

        return new MstTransparencyService(client, null, null, logVerbose, logWarning, logError);
    }
}
