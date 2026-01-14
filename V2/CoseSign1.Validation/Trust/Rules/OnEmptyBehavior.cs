// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Rules;

/// <summary>
/// Controls how quantifiers behave when a fact set is available but empty.
/// </summary>
public enum OnEmptyBehavior
{
    /// <summary>
    /// Treat an empty available set as allowed.
    /// </summary>
    Allow,

    /// <summary>
    /// Treat an empty available set as denied.
    /// </summary>
    Deny
}
