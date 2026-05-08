// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json;

using System.Text.Json;
using System.Text.Json.Nodes;

/// <summary>
/// Public-facing constants for the cose-tp-json/v1 frontend (frontend id, media types, file
/// extension, and the JSON parsing options that accept JSONC documents).
/// </summary>
public static class CoseTpJsonOptions
{
    /// <summary>The stable frontend identifier embedded in user documents and diagnostics.</summary>
    public const string FrontendId = AssemblyStrings.FrontendId;

    /// <summary>The conventional file extension (<c>.coseTrustPolicy.json</c>) for documents.</summary>
    public const string FileExtension = AssemblyStrings.FileExtension;

    /// <summary>Canonical raw-GitHub URL hosting the schema (D7).</summary>
    public const string SchemaUrl = AssemblyStrings.SchemaUrl;

    /// <summary>The IANA media type for canonical documents.</summary>
    public const string MediaType = AssemblyStrings.MediaTypeJson;

    /// <summary>
    /// Gets the recommended <see cref="JsonDocumentOptions"/> for parsing a
    /// <c>.coseTrustPolicy.json</c> document. Permits JSONC comments (<see cref="JsonCommentHandling.Skip"/>)
    /// and trailing commas — the translator never sees the comment text after parsing, so
    /// no comment-stripping pass is required.
    /// </summary>
    public static JsonDocumentOptions ParseOptions => new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        MaxDepth = MaximumDocumentDepth,
    };

    /// <summary>
    /// Gets the recommended <see cref="JsonNodeOptions"/> for the <see cref="System.Text.Json.Nodes.JsonNode"/>
    /// projection. Mirrors <see cref="ParseOptions"/> in case-sensitive property handling.
    /// </summary>
    public static JsonNodeOptions NodeOptions => new()
    {
        PropertyNameCaseInsensitive = false,
    };

    /// <summary>
    /// Maximum recursion depth permitted in a parsed document. Bounded against stack-exhaustion
    /// via deeply nested arrays / objects (§6.5.4 #6).
    /// </summary>
    public const int MaximumDocumentDepth = 64;
}
