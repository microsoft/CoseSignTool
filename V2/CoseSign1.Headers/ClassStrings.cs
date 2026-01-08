// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Headers;

internal static class ClassStrings
{
    internal const string UnsupportedCwtClaimValueType = "Unsupported CWT claim value type: {0}";

    internal const string DefaultSubject = "unknown.intent";
    internal const string ToStringIssuerFormat = "Issuer: {0}";
    internal const string ToStringSubjectFormat = "Subject: {0}";
    internal const string ToStringAudienceFormat = "Audience: {0}";
    internal const string ToStringExpiresFormat = "Expires: {0:o}";
    internal const string ToStringNotBeforeFormat = "Not Before: {0:o}";
    internal const string ToStringIssuedAtFormat = "Issued At: {0:o}";
    internal const string ToStringCwtIdFormat = "CWT ID: {0}";
    internal const string ToStringCustomClaimsCountFormat = "Custom Claims: {0}";
    internal const string ToStringByteArraySummaryFormat = "[{0} bytes]";
    internal const string ToStringNullPlaceholder = "[null]";
    internal const string ToStringCustomClaimEntryFormat = "  [{0}]: {1}";

    internal const string ErrorIssuerCannotBeNullOrWhitespace = "Issuer cannot be null or whitespace.";
    internal const string ErrorSubjectCannotBeNullOrWhitespace = "Subject cannot be null or whitespace.";
    internal const string ErrorAudienceCannotBeNullOrWhitespace = "Audience cannot be null or whitespace.";
    internal const string ErrorCwtIdCannotBeNullOrEmpty = "CWT ID cannot be null or empty.";

    internal const string TraceInitializedWithNoClaimsFormat = "CwtClaimsHeaderContributor: Initialized with no claims (placement={0}, label={1}).";
    internal const string TraceInitializedWithClaimsFormat = "CwtClaimsHeaderContributor: Initialized with claims from CwtClaims object (placement={0}, label={1}).";

    internal const string TraceSetIssuerFormat = "CwtClaimsHeaderContributor: Set issuer to '{0}'.";
    internal const string TraceSetSubjectFormat = "CwtClaimsHeaderContributor: Set subject to '{0}'.";
    internal const string TraceSetAudienceFormat = "CwtClaimsHeaderContributor: Set audience to '{0}'.";

    internal const string TraceSetExpirationTimeFormat = "CwtClaimsHeaderContributor: Set expiration time to {0}.";
    internal const string TraceSetNotBeforeTimeFormat = "CwtClaimsHeaderContributor: Set not before time to {0}.";
    internal const string TraceSetIssuedAtTimeFormat = "CwtClaimsHeaderContributor: Set issued at time to {0}.";
    internal const string TraceSetCwtIdFormat = "CwtClaimsHeaderContributor: Set CWT ID (length: {0} bytes).";
    internal const string TraceSetCustomClaimFormat = "CwtClaimsHeaderContributor: Set custom claim {0} with value type {1}.";

    internal const string TraceSkippingProtectedHeadersUnprotectedOnly = "CwtClaimsHeaderContributor: Skipping protected headers (placement=UnprotectedOnly).";
    internal const string TraceSkippingUnprotectedHeadersProtectedOnly = "CwtClaimsHeaderContributor: Skipping unprotected headers (placement=ProtectedOnly).";
    internal const string TraceMergingWithExistingClaims = "CwtClaimsHeaderContributor: Merging with existing CWT claims.";
    internal const string TraceAddedClaimsToHeaders = "CwtClaimsHeaderContributor: Added CWT claims to headers.";
    internal const string TraceNoClaimsToAdd = "CwtClaimsHeaderContributor: No claims to add to headers.";

    internal const string TraceAutoPopulatedIssuedAtFormat = "CwtClaimsHeaderContributor: Auto-populated IssuedAt to {0}.";
    internal const string TraceAutoPopulatedNotBeforeFormat = "CwtClaimsHeaderContributor: Auto-populated NotBefore to {0}.";
}
