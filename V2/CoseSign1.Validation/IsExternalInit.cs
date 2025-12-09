// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#if NETSTANDARD2_0
namespace System.Runtime.CompilerServices
{
    // Polyfill for init-only properties in netstandard2.0
    internal static class IsExternalInit { }
}
#endif
