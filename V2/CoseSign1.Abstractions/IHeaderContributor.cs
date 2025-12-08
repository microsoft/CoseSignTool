using System.Security.Cryptography.Cose;

namespace CoseSign1.Abstractions;

/// <summary>
/// Defines how to handle conflicts when a header already exists in the map.
/// </summary>
public enum HeaderMergeStrategy
{
    /// <summary>
    /// Throw an exception if the header already exists.
    /// This is the safest default behavior.
    /// </summary>
    Fail,
    
    /// <summary>
    /// Skip adding the header if it already exists (keep existing value).
    /// </summary>
    KeepExisting,
    
    /// <summary>
    /// Replace the existing header value with the new one.
    /// </summary>
    Replace,
    
    /// <summary>
    /// Allow the contributor to decide based on the existing value.
    /// The contributor's Contribute method will be called and can inspect existing headers.
    /// </summary>
    Custom
}

/// <summary>
/// Context information provided to header contributors during signing.
/// Includes access to the signing key for header derivation.
/// </summary>
public class HeaderContributorContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="HeaderContributorContext"/> class.
    /// </summary>
    public HeaderContributorContext(SigningContext signingContext, ISigningKey signingKey)
    {
        SigningContext = signingContext ?? throw new ArgumentNullException(nameof(signingContext));
        SigningKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey));
    }

    /// <summary>
    /// Gets the signing context (payload, content type, etc.).
    /// </summary>
    public SigningContext SigningContext { get; }
    
    /// <summary>
    /// Gets the signing key being used for the operation.
    /// Contributors can access key metadata via SigningKey.Metadata.
    /// </summary>
    public ISigningKey SigningKey { get; }
}

/// <summary>
/// Contributes headers to COSE messages based on sign-time context.
/// IMPORTANT: Contributors are invoked at sign-time, not at service init-time.
/// THREAD-SAFETY: Implementations MUST be thread-safe as they may be called concurrently.
/// Contributors should be immutable or use thread-safe operations.
/// ORDER: The signing service controls the order in which contributors are invoked.
/// </summary>
public interface IHeaderContributor
{
    /// <summary>
    /// Gets the merge strategy for handling conflicts when headers already exist.
    /// Default behavior should be Fail for safety.
    /// </summary>
    HeaderMergeStrategy MergeStrategy { get; }
    
    /// <summary>
    /// Contributes protected headers. Called at sign-time with full context.
    /// MUST be thread-safe - may be called concurrently from multiple threads.
    /// 
    /// If MergeStrategy is Custom, this method should check for existing headers
    /// and decide whether to add, skip, or modify them.
    /// </summary>
    /// <param name="headers">The header map to contribute to. May already contain headers.</param>
    /// <param name="context">Context including signing context and signing key (which provides metadata).</param>
    void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);
    
    /// <summary>
    /// Contributes unprotected headers. Called at sign-time with full context.
    /// MUST be thread-safe - may be called concurrently from multiple threads.
    /// 
    /// If MergeStrategy is Custom, this method should check for existing headers
    /// and decide whether to add, skip, or modify them.
    /// </summary>
    /// <param name="headers">The header map to contribute to. May already contain headers.</param>
    /// <param name="context">Context including signing context and signing key (which provides metadata).</param>
    void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context);
}
