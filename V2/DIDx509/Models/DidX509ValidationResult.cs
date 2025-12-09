// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Models;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Represents the result of DID:X509 validation.
/// </summary>
public sealed class DidX509ValidationResult
{
    /// <summary>
    /// Gets a value indicating whether the validation succeeded.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets the validation errors, if any.
    /// </summary>
    public IReadOnlyList<string> Errors { get; }

    /// <summary>
    /// Gets the parsed DID identifier.
    /// </summary>
    public DidX509ParsedIdentifier? ParsedDid { get; }

    /// <summary>
    /// Gets the certificate chain model.
    /// </summary>
    public CertificateChainModel? ChainModel { get; }

    private DidX509ValidationResult(
        bool isValid,
        IReadOnlyList<string> errors,
        DidX509ParsedIdentifier? parsedDid = null,
        CertificateChainModel? chainModel = null)
    {
        IsValid = isValid;
        Errors = errors ?? Array.Empty<string>();
        ParsedDid = parsedDid;
        ChainModel = chainModel;
    }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    public static DidX509ValidationResult Success(DidX509ParsedIdentifier parsedDid, CertificateChainModel chainModel)
    {
        return new DidX509ValidationResult(true, Array.Empty<string>(), parsedDid, chainModel);
    }

    /// <summary>
    /// Creates a failed validation result.
    /// </summary>
    public static DidX509ValidationResult Failure(params string[] errors)
    {
        return new DidX509ValidationResult(false, errors.ToList());
    }

    /// <summary>
    /// Creates a failed validation result.
    /// </summary>
    public static DidX509ValidationResult Failure(IEnumerable<string> errors)
    {
        return new DidX509ValidationResult(false, errors.ToList());
    }
}
