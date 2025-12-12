// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool;

/// <summary>
/// Exit codes for the CoseSignTool application.
/// Following POSIX conventions where 0 = success and non-zero = error.
/// </summary>
public enum ExitCode
{
    /// <summary>
    /// Command completed successfully.
    /// </summary>
    Success = 0,

    /// <summary>
    /// General error occurred.
    /// </summary>
    GeneralError = 1,

    /// <summary>
    /// Invalid command-line arguments provided.
    /// </summary>
    InvalidArguments = 2,

    /// <summary>
    /// Required file was not found.
    /// </summary>
    FileNotFound = 3,

    /// <summary>
    /// Required certificate was not found.
    /// </summary>
    CertificateNotFound = 4,

    /// <summary>
    /// Error loading or using certificate.
    /// </summary>
    CertificateError = 5,

    /// <summary>
    /// Signing operation failed.
    /// </summary>
    SigningFailed = 10,

    /// <summary>
    /// Validation operation failed.
    /// </summary>
    ValidationFailed = 20,

    /// <summary>
    /// Signature verification failed - signature is invalid.
    /// </summary>
    InvalidSignature = 21,

    /// <summary>
    /// Verification operation failed.
    /// </summary>
    VerificationFailed = 22,

    /// <summary>
    /// Certificate has expired.
    /// </summary>
    CertificateExpired = 23,

    /// <summary>
    /// Certificate is not trusted.
    /// </summary>
    UntrustedCertificate = 24,

    /// <summary>
    /// Plugin loading or execution failed.
    /// </summary>
    PluginError = 30,

    /// <summary>
    /// Inspection operation failed.
    /// </summary>
    InspectionFailed = 40
}
