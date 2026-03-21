// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories.Direct;

using System.Security.Cryptography.Cose;
using Cose.Abstractions;
using CoseSign1.Abstractions;

/// <summary>
/// Header contributor that adds the content-type header (label 3) to protected headers.
/// This is a mandatory header for direct COSE Sign1 messages.
/// </summary>
public sealed class ContentTypeHeaderContributor : ICoseSign1HeaderContributor
{
    /// <summary>
    /// Gets the merge strategy. Uses Replace to allow overriding existing content-type headers.
    /// </summary>
    public HeaderMergeStrategy MergeStrategy => HeaderMergeStrategy.Replace;

    /// <inheritdoc/>
    /// <remarks>
    /// No-op without signing context. Content-type requires signing context.
    /// </remarks>
    public void ContributeProtectedHeaders(CoseHeaderMap headers)
    {
        // Content-type requires signing context for the content type value
    }

    /// <inheritdoc/>
    /// <remarks>
    /// No-op without signing context.
    /// </remarks>
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers)
    {
        // No unprotected headers for content-type
    }

    /// <summary>
    /// Contributes the content-type header to protected headers.
    /// Adds or updates CoseHeaderLabel.ContentType (label 3) with the value from SigningContext.
    /// </summary>
    /// <param name="headers">The header map to contribute to.</param>
    /// <param name="context">Context including signing context with content type.</param>
    public void ContributeProtectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        var contentType = context.SigningContext.ContentType;
        var contentTypeValue = CoseHeaderValue.FromString(contentType);

        // Use defensive coding: check if header exists before adding
        if (headers.ContainsKey(CoseHeaderLabel.ContentType))
        {
            headers[CoseHeaderLabel.ContentType] = contentTypeValue;
        }
        else
        {
            headers.Add(CoseHeaderLabel.ContentType, contentTypeValue);
        }
    }

    /// <summary>
    /// Does not contribute any unprotected headers.
    /// Content-type must be in protected headers per COSE specification.
    /// </summary>
    /// <param name="headers">The header map to contribute to.</param>
    /// <param name="context">Context including signing context.</param>
    public void ContributeUnprotectedHeaders(CoseHeaderMap headers, HeaderContributorContext context)
    {
        // Content-type is only added to protected headers
    }
}