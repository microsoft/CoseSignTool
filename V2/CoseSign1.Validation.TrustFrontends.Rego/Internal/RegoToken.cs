// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego.Internal;

/// <summary>
/// One lexical token produced by <see cref="RegoTokenizer"/>. Holds the kind, the raw text,
/// and the (line, column) origin (1-based) for diagnostics' source locations.
/// </summary>
internal readonly record struct RegoToken(
    RegoTokenKind Kind,
    string Text,
    int Line,
    int Column);
