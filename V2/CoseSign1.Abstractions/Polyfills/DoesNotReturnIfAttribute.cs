// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#if !NET6_0_OR_GREATER

namespace System.Diagnostics.CodeAnalysis
{
    using System;

    /// <summary>
    /// Specifies that the method will not return if the associated Boolean parameter is passed the specified value.
    /// </summary>
    /// <remarks>
    /// This is a polyfill for netstandard2.0. On .NET Core 3.0+, this attribute is built-in.
    /// </remarks>
    [AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false)]
    internal sealed class DoesNotReturnIfAttribute : Attribute
    {
        /// <summary>
        /// Initializes a new instance of <see cref="DoesNotReturnIfAttribute"/>.
        /// </summary>
        /// <param name="parameterValue">The condition parameter value that causes the method not to return.</param>
        public DoesNotReturnIfAttribute(bool parameterValue)
        {
            ParameterValue = parameterValue;
        }

        /// <summary>
        /// Gets the condition parameter value that causes the method not to return.
        /// </summary>
        public bool ParameterValue { get; }
    }
}

#endif
