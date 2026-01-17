// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#if !NET6_0_OR_GREATER

namespace System.Runtime.CompilerServices
{
    using System;

    /// <summary>
    /// Allows capturing of the expression passed to a method parameter.
    /// This attribute is used by the compiler to support CallerArgumentExpression.
    /// </summary>
    /// <remarks>
    /// This is a polyfill for netstandard2.0. On .NET 6+, this attribute is built-in.
    /// </remarks>
    [AttributeUsage(AttributeTargets.Parameter, AllowMultiple = false, Inherited = false)]
    internal sealed class CallerArgumentExpressionAttribute : Attribute
    {
        /// <summary>
        /// Initializes a new instance of <see cref="CallerArgumentExpressionAttribute"/>.
        /// </summary>
        /// <param name="parameterName">The name of the parameter whose expression should be captured.</param>
        public CallerArgumentExpressionAttribute(string parameterName)
        {
            ParameterName = parameterName;
        }

        /// <summary>
        /// Gets the name of the parameter whose expression should be captured.
        /// </summary>
        public string ParameterName { get; }
    }
}

#endif
