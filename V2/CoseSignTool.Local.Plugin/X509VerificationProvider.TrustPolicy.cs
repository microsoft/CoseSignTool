// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin;

using System.CommandLine.Parsing;
using CoseSign1.Certificates.Validation;
using CoseSign1.Validation;
using CoseSignTool.Abstractions;

public partial class X509VerificationProvider : IVerificationProviderWithTrustPolicy
{
    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException"><paramref name="parseResult"/> is <see langword="null"/>.</exception>
    public TrustPolicy? CreateTrustPolicy(ParseResult parseResult, VerificationContext context)
    {
        if (parseResult == null)
        {
            throw new ArgumentNullException(nameof(parseResult));
        }

        // If the user explicitly allows untrusted roots, do not require X509 chain trust.
        // Chain validation may still run for diagnostics / metadata, but policy remains permissive.
        if (IsAllowUntrusted(parseResult))
        {
            return TrustPolicy.Or();
        }

        return X509TrustPolicies.RequireTrustedChain();
    }
}
