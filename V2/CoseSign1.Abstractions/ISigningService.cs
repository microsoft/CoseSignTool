// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.Cose;

namespace CoseSign1.Abstractions;

/// <summary>
/// Represents a service capable of signing COSE messages with strongly-typed signing options.
/// Emits CoseSigner instances (from .NET runtime) for signing operations.
/// Uses an ISigningKey to get the underlying CoseKey and applies headers.
/// The generic parameter declares the specific options type this service uses.
/// </summary>
/// <typeparam name="TSigningOptions">The type of signing options this service uses.</typeparam>
public interface ISigningService<out TSigningOptions> : IDisposable
    where TSigningOptions : SigningOptions
{
    /// <summary>
    /// Creates a CoseSigner for the signing operation with appropriate headers.
    /// The CoseSigner contains the CoseKey (from ISigningKey) and all headers.
    /// 
    /// Process:
    /// 1. Gets ISigningKey via GetSigningKey(context)
    /// 2. Gets CoseKey from ISigningKey.GetCoseKey()
    /// 3. Builds headers using IHeaderContributors (with ISigningKey context)
    /// 4. Creates and returns CoseSigner with CoseKey + headers
    /// </summary>
    /// <param name="context">The signing context (payload info, custom headers, etc.)</param>
    /// <returns>A CoseSigner ready to sign the message</returns>
    CoseSigner GetCoseSigner(SigningContext context);
    
    /// <summary>
    /// Creates a new instance of the signing options appropriate for this signing service.
    /// The type is declared by the generic parameter TSigningOptions.
    /// </summary>
    /// <returns>A new instance of the service-specific signing options.</returns>
    TSigningOptions CreateSigningOptions();
    
    /// <summary>
    /// Gets a value indicating whether this is a remote signing service.
    /// </summary>
    bool IsRemote { get; }
    
    /// <summary>
    /// Gets metadata about the signing service.
    /// Used by header contributors to make service-level decisions.
    /// Examples: service name, version, compliance requirements (SCITT, etc.)
    /// </summary>
    SigningServiceMetadata ServiceMetadata { get; }
}
