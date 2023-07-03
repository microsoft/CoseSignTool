// ---------------------------------------------------------------------------
// <copyright file="X509CommonNameValidator.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseSign1.Certificates.Local.Validators;

/// <summary>
/// Class to validate a common name from a given <see cref="X509Certificate2"/> object.
/// </summary>
public class X509CommonNameValidator : X509Certificate2MessageValidator
{
    private readonly string RequiredCommonName;

    /// <summary>
    /// The required common name for the <see cref="X509Certificate2"/>.
    /// </summary>
    /// <param name="requiredCommonName"></param>
    /// <param name="allowUnprotected"></param>
    public X509CommonNameValidator(
        string requiredCommonName,
        bool allowUnprotected = false) : base(allowUnprotected)
    {
        if (string.IsNullOrWhiteSpace(requiredCommonName))
        {
            throw new ArgumentOutOfRangeException(nameof(requiredCommonName),"Required Common Name Must Be Provided");
        }
        RequiredCommonName = requiredCommonName;
    }

    /// <inheritdoc/>
    protected override CoseSign1ValidationResult ValidateCertificate(
        X509Certificate2 signingCertificate,
        List<X509Certificate2>? certChain,
        List<X509Certificate2>? extraCertificates)
    {
        CoseSign1ValidationResult returnResult = new(GetType());

        // perform the common name validation.
        try
        {
            ValidateCommonName(signingCertificate, RequiredCommonName);
        }
        catch (CoseValidationException ex)
        {
            returnResult.ResultMessage = ex.ToString();
            returnResult.Includes ??= new List<object>();
            returnResult.Includes.Add(ex);
            return returnResult;
        }

        returnResult.ResultMessage = $"Certificate [{signingCertificate.Thumbprint}] subject name: {signingCertificate.SubjectName.Format(multiLine: false)} validated against the required name of {RequiredCommonName}";
        returnResult.PassedValidation = true;
        return returnResult;
    }

    /// <summary>
    /// Validates that the Common Name provided matches the common name of the certificate.
    /// </summary>
    /// <param name="cert">The certificate to check.</param>
    /// <param name="commonName">The certificate Common Name to require.</param>
    /// <exception cref="CoseValidationException">The certificate did not match the required Common Name.</exception>
    /// <remarks>The match performed by ValidateCommonName is case-sensitive.</remarks>
    public static void ValidateCommonName(X509Certificate2 cert, string? commonName)
    {
        if (commonName is not null)
        {
            string signingCertSubjectName = cert.SubjectName.Format(multiLine: false);

            if (!commonName.Equals(signingCertSubjectName, StringComparison.Ordinal))
            {
                throw new CoseValidationException($"Signing certificate common name [{signingCertSubjectName}] does not match required name [{commonName}]");
            }
        }
    }
}
