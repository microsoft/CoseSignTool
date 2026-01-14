// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ============================================================================
// POLYFILLS AND GUARD CLASS FOR CROSS-FRAMEWORK COMPATIBILITY
// ============================================================================
//
// This file provides two categories of functionality:
//
// 1. COMPILER SUPPORT ATTRIBUTES (internal, netstandard2.0 only)
//    - CallerArgumentExpressionAttribute: Enables automatic parameter name capture
//    - NotNullAttribute, DoesNotReturnIfAttribute: Nullability analysis support
//    - RequiredMemberAttribute, CompilerFeatureRequiredAttribute: For 'required' keyword
//    These are internal because they're only needed by the compiler and shouldn't
//    be exposed as public API.
//
// 2. GUARD CLASS (public, all frameworks)
//    - Guard.ThrowIfNull(): Replaces ArgumentNullException.ThrowIfNull (.NET 6+)
//    - Guard.ThrowIfDisposed(): Replaces ObjectDisposedException.ThrowIf (.NET 7+)
//    This is public because it provides a unified API that consuming code should
//    use directly, regardless of target framework.
//
// USAGE:
//    // Instead of: ArgumentNullException.ThrowIfNull(param);
//    Guard.ThrowIfNull(param);
//
//    // Instead of: ObjectDisposedException.ThrowIf(_disposed, this);
//    Guard.ThrowIfDisposed(_disposed, this);
//
// WHY A UNIFIED GUARD CLASS?
//    - Consistent API across all target frameworks
//    - No conditional compilation needed in consuming code
//    - Calling code doesn't need to know which framework it's running on
//    - On .NET 6+/.NET 7+, we delegate to the native methods for best performance
//    - On netstandard2.0, we provide equivalent functionality
//
// ============================================================================
namespace CoseSign1.Abstractions
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Runtime.CompilerServices;

    /// <summary>
    /// Provides guard methods for argument validation that work consistently across all target frameworks.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class provides a unified API for common validation patterns that were introduced in later
    /// versions of .NET:
    /// </para>
    /// <list type="bullet">
    ///   <item>
    ///     <description><see cref="ThrowIfNull{T}(T, string)"/> - Equivalent to <c>ArgumentNullException.ThrowIfNull</c> (.NET 6+)</description>
    ///   </item>
    ///   <item>
    ///     <description><see cref="ThrowIfDisposed(bool, object)"/> - Equivalent to <c>ObjectDisposedException.ThrowIf</c> (.NET 7+)</description>
    ///   </item>
    /// </list>
    /// <para>
    /// <b>Why use Guard instead of the native methods?</b>
    /// </para>
    /// <para>
    /// When targeting multiple frameworks (e.g., netstandard2.0 and net10.0), using the native methods
    /// requires conditional compilation (<c>#if NET6_0_OR_GREATER</c>) throughout your code. The Guard
    /// class eliminates this complexity by providing a single API that works everywhere.
    /// </para>
    /// <para>
    /// On .NET 6+ and .NET 7+, the Guard methods delegate to the native implementations for optimal
    /// performance. On netstandard2.0, equivalent functionality is provided.
    /// </para>
    /// <para>
    /// <b>Example usage:</b>
    /// </para>
    /// <code>
    /// public void ProcessData(string data, Stream output)
    /// {
    ///     Guard.ThrowIfNull(data);
    ///     Guard.ThrowIfNull(output);
    ///     Guard.ThrowIfDisposed(_disposed, this);
    ///     
    ///     // ... method implementation
    /// }
    /// </code>
    /// </remarks>
    public static class Guard
    {
        [ExcludeFromCodeCoverage]
        internal static class ClassStrings
        {
            public const string ValueCannotBeEmptyOrWhiteSpace = "The value cannot be an empty string or composed entirely of whitespace.";
        }

        /// <summary>
        /// Throws an <see cref="ArgumentNullException"/> if <paramref name="argument"/> is <see langword="null"/>.
        /// </summary>
        /// <typeparam name="T">The type of the argument.</typeparam>
        /// <param name="argument">The reference type argument to validate as non-null.</param>
        /// <param name="paramName">
        /// The name of the parameter with which <paramref name="argument"/> corresponds.
        /// If not specified, the compiler will automatically capture the argument expression.
        /// </param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="argument"/> is <see langword="null"/>.</exception>
        /// <example>
        /// <code>
        /// public void SetName(string name)
        /// {
        ///     Guard.ThrowIfNull(name);
        ///     _name = name;
        /// }
        /// </code>
        /// </example>
        public static void ThrowIfNull<T>(
            [NotNull] T? argument,
            [CallerArgumentExpression(nameof(argument))] string? paramName = null)
        {
#if NET6_0_OR_GREATER
            ArgumentNullException.ThrowIfNull(argument, paramName);
#else
            if (argument is null)
            {
                throw new ArgumentNullException(paramName);
            }
#endif
        }

        /// <summary>
        /// Throws an <see cref="ArgumentException"/> if <paramref name="argument"/> is <see langword="null"/>, empty, or consists only of white-space characters.
        /// </summary>
        /// <param name="argument">The string argument to validate.</param>
        /// <param name="paramName">
        /// The name of the parameter with which <paramref name="argument"/> corresponds.
        /// If not specified, the compiler will automatically capture the argument expression.
        /// </param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="argument"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">Thrown when <paramref name="argument"/> is empty or consists only of white-space characters.</exception>
        /// <example>
        /// <code>
        /// public void SetName(string name)
        /// {
        ///     Guard.ThrowIfNullOrWhiteSpace(name);
        ///     _name = name;
        /// }
        /// </code>
        /// </example>
        public static void ThrowIfNullOrWhiteSpace(
            [NotNull] string? argument,
            [CallerArgumentExpression(nameof(argument))] string? paramName = null)
        {
#if NET8_0_OR_GREATER
            ArgumentException.ThrowIfNullOrWhiteSpace(argument, paramName);
#else
            if (argument is null)
            {
                throw new ArgumentNullException(paramName);
            }

            if (string.IsNullOrWhiteSpace(argument))
            {
                throw new ArgumentException(ClassStrings.ValueCannotBeEmptyOrWhiteSpace, paramName);
            }
#endif
        }

        /// <summary>
        /// Throws an <see cref="ObjectDisposedException"/> if <paramref name="condition"/> is <see langword="true"/>.
        /// </summary>
        /// <param name="condition">The condition to evaluate. Typically this is a <c>_disposed</c> field.</param>
        /// <param name="instance">The object instance that may be disposed. Its type name will be included in the exception message.</param>
        /// <exception cref="ObjectDisposedException">Thrown when <paramref name="condition"/> is <see langword="true"/>.</exception>
        /// <example>
        /// <code>
        /// private bool _disposed;
        /// 
        /// public void DoWork()
        /// {
        ///     Guard.ThrowIfDisposed(_disposed, this);
        ///     // ... method implementation
        /// }
        /// </code>
        /// </example>
        public static void ThrowIfDisposed(
            [DoesNotReturnIf(true)] bool condition,
            object instance)
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(condition, instance);
#else
            if (condition)
            {
                throw new ObjectDisposedException(instance?.GetType().FullName);
            }
#endif
        }

        /// <summary>
        /// Throws an <see cref="ObjectDisposedException"/> if <paramref name="condition"/> is <see langword="true"/>.
        /// </summary>
        /// <param name="condition">The condition to evaluate. Typically this is a <c>_disposed</c> field.</param>
        /// <param name="type">The type whose full name should be included in the exception message.</param>
        /// <exception cref="ObjectDisposedException">Thrown when <paramref name="condition"/> is <see langword="true"/>.</exception>
        /// <example>
        /// <code>
        /// private bool _disposed;
        /// 
        /// public void DoWork()
        /// {
        ///     Guard.ThrowIfDisposed(_disposed, typeof(MyClass));
        ///     // ... method implementation
        /// }
        /// </code>
        /// </example>
        public static void ThrowIfDisposed(
            [DoesNotReturnIf(true)] bool condition,
            Type type)
        {
#if NET7_0_OR_GREATER
            ObjectDisposedException.ThrowIf(condition, type);
#else
            if (condition)
            {
                throw new ObjectDisposedException(type?.FullName);
            }
#endif
        }
    }
}

#if !NET6_0_OR_GREATER

namespace System.Runtime.CompilerServices
{
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

namespace System.Diagnostics.CodeAnalysis
{
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

namespace System.Runtime.CompilerServices
{
    /// <summary>
    /// Specifies that a type has required members or that a member is required.
    /// This is a polyfill for netstandard2.0. On .NET 7+, this attribute is built-in.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Field | AttributeTargets.Property, AllowMultiple = false, Inherited = false)]
    internal sealed class RequiredMemberAttribute : Attribute
    {
    }

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
