// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#if !NET6_0_OR_GREATER

namespace System.Runtime.CompilerServices
{
    using System;

    /// <summary>
    /// Indicates that compiler support for a particular feature is required for the location where this attribute is applied.
    /// This is a polyfill for netstandard2.0. On .NET 7+, this attribute is built-in.
    /// </summary>
    [AttributeUsage(AttributeTargets.All, AllowMultiple = true, Inherited = false)]
    internal sealed class CompilerFeatureRequiredAttribute : Attribute
    {
        /// <summary>
        /// The name of the compiler feature.
        /// </summary>
        public const string RefStructs = nameof(RefStructs);

        /// <summary>
        /// The name of the required members feature.
        /// </summary>
        public const string RequiredMembers = nameof(RequiredMembers);

        /// <summary>
        /// Initializes a new instance of <see cref="CompilerFeatureRequiredAttribute"/>.
        /// </summary>
        /// <param name="featureName">The name of the required compiler feature.</param>
        public CompilerFeatureRequiredAttribute(string featureName)
        {
            FeatureName = featureName;
        }

        /// <summary>
        /// Gets the name of the compiler feature.
        /// </summary>
        public string FeatureName { get; }

        /// <summary>
        /// Gets or sets a value indicating whether the compiler can choose to allow access to the location where this attribute is applied if it does not understand <see cref="FeatureName"/>.
        /// </summary>
        public bool IsOptional { get; init; }
    }
}

#endif
