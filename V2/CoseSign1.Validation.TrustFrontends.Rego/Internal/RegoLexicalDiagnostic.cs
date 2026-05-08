// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego.Internal;

/// <summary>
/// One lexical-stage diagnostic produced by <see cref="RegoTokenizer"/> (e.g. unterminated
/// string, invalid escape, malformed number). Lifted into a <see cref="CoseSign1.Validation.Trust.Frontends.TrustPolicyTranslationDiagnostic"/>
/// by the parser before being returned to the host.
/// </summary>
internal readonly record struct RegoLexicalDiagnostic(string Message, int Line, int Column);
