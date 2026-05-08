// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego.Internal;

using System.Collections.Generic;

/// <summary>
/// Abstract base for the Rego-subset AST. Closed hierarchy — every concrete node lives in
/// this file so adding a new node kind requires touching the hierarchy and the lowerer in
/// the same change-set (the parser/lowerer pair is the contract surface).
/// </summary>
internal abstract record RegoValueNode(int Line, int Column);

/// <summary>An object literal: <c>{"k": v, ...}</c>. Keys are string literals (Rego restriction).</summary>
internal sealed record RegoObjectNode(List<RegoObjectEntry> Entries, int Line, int Column) : RegoValueNode(Line, Column);

/// <summary>One entry in an object literal: a string key paired with a value node.</summary>
internal sealed record RegoObjectEntry(string Key, RegoValueNode Value, int KeyLine, int KeyColumn);

/// <summary>An array literal: <c>[a, b, c]</c>.</summary>
internal sealed record RegoArrayNode(List<RegoValueNode> Items, int Line, int Column) : RegoValueNode(Line, Column);

/// <summary>A scalar literal — string, number, bool, or null.</summary>
internal sealed record RegoScalarNode(RegoScalarKind Kind, string Text, int Line, int Column) : RegoValueNode(Line, Column);

/// <summary>An <c>input.&lt;name&gt;</c> reference. The lowerer rewrites this to a <c>{"$param": "&lt;name&gt;"}</c> JSON node.</summary>
internal sealed record RegoInputRefNode(string ParameterName, int Line, int Column) : RegoValueNode(Line, Column);

/// <summary>Scalar kind discriminator for <see cref="RegoScalarNode"/>.</summary>
internal enum RegoScalarKind
{
    /// <summary>Decoded string literal.</summary>
    String,

    /// <summary>Numeric literal — integer or decimal.</summary>
    Number,

    /// <summary>Boolean true.</summary>
    True,

    /// <summary>Boolean false.</summary>
    False,

    /// <summary>The null literal.</summary>
    Null,
}
