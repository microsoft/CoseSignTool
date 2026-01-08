// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace System.Runtime.CompilerServices
{
    /// <summary>
    /// Defines <c>System.Runtime.CompilerServices.IsExternalInit</c> for <c>netstandard2.0</c> builds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Why this file exists:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <description>
    /// This repo uses C# <c>init</c>-only setters (e.g., <c>public string Name { get; init; }</c>).
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// The C# compiler encodes <c>init</c>-only semantics by emitting metadata that references the
    /// <c>System.Runtime.CompilerServices.IsExternalInit</c> type. If that type is not available in the
    /// target framework, compilation fails.
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// <c>netstandard2.0</c> does not ship this type, so we provide a minimal definition here.
    /// Placing it in <c>CoseSign1.Abstractions</c> makes it available to other <c>netstandard2.0</c>
    /// projects via a normal project/assembly reference.
    /// </description>
    /// </item>
    /// </list>
    ///
    /// <para>
    /// Runtime impact:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <description>
    /// This is a compile-time compatibility shim only; the type has no behavior.
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// The type name matches the one provided by newer target frameworks; when targeting those
    /// frameworks, you should not include a second definition to avoid conflicts.
    /// </description>
    /// </item>
    /// </list>
    ///
    /// <para>
    /// When it is safe to remove:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <description>
    /// If the repo stops targeting <c>netstandard2.0</c> (or all consumers target frameworks that
    /// include <c>IsExternalInit</c>), this file can be removed.
    /// </description>
    /// </item>
    /// </list>
    ///
    /// <para>
    /// References:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <description>
    /// C# <c>init</c> keyword docs: https://learn.microsoft.com/dotnet/csharp/language-reference/keywords/init
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// C# 9 <c>init</c>-only setters proposal: https://learn.microsoft.com/dotnet/csharp/language-reference/proposals/csharp-9.0/init
    /// </description>
    /// </item>
    /// <item>
    /// <description>
    /// Runtime definition (for frameworks that include it):
    /// https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Runtime/CompilerServices/IsExternalInit.cs
    /// </description>
    /// </item>
    /// </list>
    /// </remarks>
    public static class IsExternalInit { }
}
