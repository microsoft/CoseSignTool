// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Marker interface for validators that perform cryptographic signature verification.
/// This enables higher-level orchestration (e.g., "at least one signature verifier must apply").
/// </summary>
public interface ISignatureValidator
{
}
