// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego;

using System.Text.Json.Nodes;
using CoseSign1.Validation.TrustFrontends.Rego.Internal;

/// <summary>
/// Opaque parsed-document type for <see cref="CoseSign1.Validation.Trust.Frontends.ICoseTrustPolicyFrontend{TDocument}"/>.
/// Wraps the constrained-subset AST (<see cref="RegoValueNode"/>) plus the lowered
/// <see cref="JsonNode"/> projection so <see cref="CoseTpRegoFrontend.Translate(RegoDocument, CoseSign1.Validation.Trust.Frontends.TrustPolicyTranslationContext)"/>
/// can hand the projection straight to the JSON frontend's walker.
/// </summary>
/// <remarks>
/// <para>
/// The type is intentionally minimal — a parsed Rego document for cose-tp-rego/v1 is just
/// "a JSON-shaped object literal", and that's exactly what the wrapper exposes. Holding the
/// raw <see cref="JsonNode"/> projection avoids re-lowering on every translate call when the
/// host caches the parse result (e.g. the CLI loader).
/// </para>
/// </remarks>
public sealed class RegoDocument
{
    internal RegoDocument(RegoValueNode rootAst, JsonNode? loweredRoot, string? documentSource)
    {
        RootAst = rootAst;
        LoweredRoot = loweredRoot;
        DocumentSource = documentSource;
    }

    /// <summary>Gets the parsed AST root.</summary>
    internal RegoValueNode RootAst { get; }

    /// <summary>Gets the AST lowered to a <see cref="JsonNode"/> matching the canonical schema shape.</summary>
    internal JsonNode? LoweredRoot { get; }

    /// <summary>Gets the source identifier passed in at parse time (e.g. file URI).</summary>
    internal string? DocumentSource { get; }
}
