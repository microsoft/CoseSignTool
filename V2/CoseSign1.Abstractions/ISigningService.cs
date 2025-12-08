using System.Security.Cryptography.Cose;

namespace CoseSign1.Abstractions;

/// <summary>
/// Represents a service capable of signing COSE messages.
/// Emits CoseSigner instances (from .NET runtime) for signing operations.
/// Uses an ISigningKey to get the underlying CoseKey and applies headers.
/// </summary>
public interface ISigningService : IDisposable
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
