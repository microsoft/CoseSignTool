// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Local.Plugin;

using System.CommandLine.Parsing;
using CoseSign1.Certificates.Trust.Facts;
using CoseSign1.Validation.Trust;
using CoseSignTool.Abstractions;

public partial class X509VerificationProvider : IVerificationProviderWithTrustPlanPolicy
{
    /// <inheritdoc/>
    /// <exception cref="ArgumentNullException"><paramref name="parseResult"/> is <see langword="null"/>.</exception>
    public TrustPlanPolicy? CreateTrustPlanPolicy(ParseResult parseResult, VerificationContext context)
    {
        if (parseResult == null)
        {
            throw new ArgumentNullException(nameof(parseResult));
        }

        var allowUntrusted = IsAllowUntrusted(parseResult);
        var requiredSubjectCn = GetSubjectName(parseResult);
        var requiredIssuerCn = GetIssuerName(parseResult);

        // If nothing is required and the user allows untrusted, this provider imposes no trust policy.
        if (allowUntrusted && string.IsNullOrEmpty(requiredSubjectCn) && string.IsNullOrEmpty(requiredIssuerCn))
        {
            return TrustPlanPolicy.Message(_ => _);
        }

        return TrustPlanPolicy.PrimarySigningKey(k =>
        {
            if (!allowUntrusted)
            {
                k = k.RequireFact<X509ChainTrustedFact>(
                    f => f.IsTrusted,
                    ClassStrings.X509ChainMustBeTrusted);
            }

            if (!string.IsNullOrEmpty(requiredSubjectCn))
            {
                k = k.RequireFact<X509SigningCertificateIdentityFact>(
                    f => string.Equals(ExtractCommonName(f.Subject), requiredSubjectCn, StringComparison.OrdinalIgnoreCase),
                    string.Format(ClassStrings.X509SubjectCommonNameMustMatchFormat, requiredSubjectCn));
            }

            if (!string.IsNullOrEmpty(requiredIssuerCn))
            {
                k = k.RequireFact<X509SigningCertificateIdentityFact>(
                    f => string.Equals(ExtractCommonName(f.Issuer), requiredIssuerCn, StringComparison.OrdinalIgnoreCase),
                    string.Format(ClassStrings.X509IssuerCommonNameMustMatchFormat, requiredIssuerCn));
            }

            return k;
        });
    }
}
