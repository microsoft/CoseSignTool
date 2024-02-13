// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseX509;

/// <summary>
/// A set of COSE content validation types. Content validation refers to the method used to validate
/// that the payload has not been modified.
/// </summary>
public enum ContentValidationType
{
    /// <summary>
    /// Indicates that validation on the content was not performed.
    /// </summary>
    ContentValidationNotPerformed = 0,

    /// <summary>
    /// Indicates validation using a detached payload. The payload is not included in the message.
    /// </summary>
    Detached = 1,

    /// <summary>
    /// Indicates validation using an embedded payload. The payload is included in the message.
    /// </summary>
    Embedded = 2,

    /// <summary>
    /// Indicates validation using an indirect payload. The payload is hashed using the algorithm in the COSE message
    /// and then the payload hash is compared to the embedded content.
    /// </summary>
    IndirectSignature = 3
}