// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions;

/// <summary>
/// Represents the result of executing a plugin command.
/// </summary>
public enum PluginExitCode
{
    /// <summary>
    /// The command executed successfully.
    /// </summary>
    Success = 0,

    /// <summary>
    /// Help was requested for the command.
    /// </summary>
    HelpRequested = 1,

    /// <summary>
    /// A required command line option was missing.
    /// </summary>
    MissingRequiredOption = 2,

    /// <summary>
    /// A command line argument was not recognized.
    /// </summary>
    UnknownArgument = 3,

    /// <summary>
    /// A command line argument value was invalid.
    /// </summary>
    InvalidArgumentValue = 4,

    /// <summary>
    /// A required argument value was missing.
    /// </summary>
    MissingArgumentValue = 5,

    /// <summary>
    /// A file specified by the user was not found.
    /// </summary>
    UserSpecifiedFileNotFound = 6,

    /// <summary>
    /// Certificate loading failed during signing operation.
    /// </summary>
    CertificateLoadFailure = 7,

    /// <summary>
    /// The payload could not be read during signing operation.
    /// </summary>
    PayloadReadError = 8,

    /// <summary>
    /// An indirect signature verification failed.
    /// </summary>
    IndirectSignatureVerificationFailure = 9,

    /// <summary>
    /// An unknown error occurred.
    /// </summary>
    UnknownError = 10
}
