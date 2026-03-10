// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#if !NET6_0_OR_GREATER

namespace System.Diagnostics.CodeAnalysis
{
    using System;

    /// <summary>
    /// Specifies that an output is not null even if the corresponding type allows it.
    /// </summary>
    /// <remarks>
    /// This is a polyfill for netstandard2.0. On .NET Core 3.0+, this attribute is built-in.
    /// </remarks>
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter | AttributeTargets.ReturnValue, AllowMultiple = true)]
    internal sealed class NotNullAttribute : Attribute
    {
    }
}

#endif
