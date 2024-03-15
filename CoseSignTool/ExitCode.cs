// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool;

public enum ExitCode
{
    /// <summary>
    /// The SignInternal or Validate operation succeeded.
    /// </summary>
    Success = 0,

    /// <summary>
    /// The requested command line help or did not specify a command.
    /// </summary>
    HelpRequested = 9999,

    /// <summary>
    /// A command line argument was not recognized.
    /// </summary>
    UnknownArgument = 1000,

    /// <summary>
    /// A required command line argument was missing.
    /// </summary>
    MissingRequiredOption = 1007,

    /// <summary>
    /// A non-boolean command line was given without a value.
    /// </summary>
    MissingArgumentValue = 1006,

    /// <summary>
    /// A command line argument was given an invalid value.
    /// </summary>
    InvalidArgumentValue = 1004,

    /// <summary>
    /// A user-supplied file path did not contain the specified file.
    /// </summary>
    UserSpecifiedFileNotFound = 1009,

    /// <summary>
    /// A certificate could not be loaded.
    /// </summary>
    CertificateLoadFailure = 1888,

    /// <summary>
    /// No certificate could be found in the local Certificate Store to match the specified thumbprint.
    /// </summary>
    StoreCertificateNotFound = 1889,

    /// <summary>
    /// The signature failed to validate against the trust validator.
    /// </summary>
    TrustValidationFailure = 1890,

    /// <summary>
    /// The certificate chain failed validation.
    /// </summary>
    CertificateChainValidationFailure = 1891,

    /// <summary>
    /// The signed payload did not match the original payload.
    /// </summary>
    PayloadValidationError = 1892,

    /// <summary>
    /// The payload was missing or unreadable.
    /// </summary>
    PayloadReadError = 1893,

    /// <summary>
    /// The signature file or stream could not be read, or failed to meet COSE format requirements.
    /// </summary>
    SignatureLoadError = 1894,

    /// <summary>
    /// The payload or signature file that was read had no content.
    /// </summary>
    EmptySourceFile = 1895,

    /// <summary>
    /// A user specified file was found but could not be read.
    /// </summary>
    FileUnreadable = 1896,




    /// <summary>
    /// CoseSignTool exited with an unknown error.
    /// </summary>
    UnknownError = 1950
}
