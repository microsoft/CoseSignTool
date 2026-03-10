// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Results;

/// <summary>
/// Represents the outcome kind of a validation operation.
/// </summary>
public enum ValidationResultKind
{
    /// <summary>
    /// The validator executed and succeeded.
    /// </summary>
    Success,

    /// <summary>
    /// The validator executed and failed.
    /// </summary>
    Failure,

    /// <summary>
    /// The validator did not apply (e.g., unsupported stage, missing prerequisite data).
    /// </summary>
    NotApplicable
}
