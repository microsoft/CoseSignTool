// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#if !NET6_0_OR_GREATER

namespace System.Runtime.CompilerServices
{
    using System;

    /// <summary>
    /// Specifies that a type has required members or that a member is required.
    /// This is a polyfill for netstandard2.0. On .NET 7+, this attribute is built-in.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Field | AttributeTargets.Property, AllowMultiple = false, Inherited = false)]
    internal sealed class RequiredMemberAttribute : Attribute
    {
    }
}

#endif
