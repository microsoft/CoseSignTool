// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego;

/// <summary>
/// Public-facing constants for the cose-tp-rego/v1 frontend (frontend id, media type, file
/// extension). Mirrors <c>CoseTpJsonOptions</c> for symmetry between frontends.
/// </summary>
public static class CoseTpRegoOptions
{
    /// <summary>The stable frontend identifier embedded in user documents and diagnostics.</summary>
    public const string FrontendId = AssemblyStrings.FrontendId;

    /// <summary>The conventional file extension (<c>.coseTrustPolicy.rego</c>) for documents.</summary>
    public const string FileExtension = AssemblyStrings.FileExtension;

    /// <summary>The IANA media type for Rego trust-policy documents.</summary>
    public const string MediaType = AssemblyStrings.MediaTypeRego;

    /// <summary>The required Rego package name (<c>package cose_trust_policy</c>).</summary>
    public const string RequiredPackage = AssemblyStrings.RequiredPackage;

    /// <summary>The required rule name (<c>policy := { ... }</c>).</summary>
    public const string PolicyRuleName = AssemblyStrings.PolicyRuleName;
}
