// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Abstractions;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Assembly-level attribute to register a default validation component provider for auto-discovery.
/// </summary>
/// <remarks>
/// <para>
/// Apply this attribute at the assembly level to register an <see cref="IDefaultValidationComponentProvider"/>
/// implementation that will be automatically discovered when callers invoke <c>message.Validate()</c>
/// without explicit configuration.
/// </para>
/// <para>
/// Multiple providers can be registered per assembly by applying the attribute multiple times.
/// </para>
/// </remarks>
/// <example>
/// In your extension package's AssemblyInfo.cs or any other file:
/// <code>
/// using CoseSign1.Validation.Abstractions;
/// 
/// [assembly: DefaultValidationComponentProvider(typeof(MyCertificateComponentProvider))]
/// [assembly: DefaultValidationComponentProvider(typeof(MyTrustComponentProvider))]
/// </code>
/// </example>
[AttributeUsage(AttributeTargets.Assembly, AllowMultiple = true)]
public sealed class DefaultValidationComponentProviderAttribute : Attribute
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ErrorTypeMustImplementInterface = "Type {0} must implement {1}.";
    }

    /// <summary>
    /// Gets the type of the provider that implements <see cref="IDefaultValidationComponentProvider"/>.
    /// </summary>
    public Type ProviderType { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultValidationComponentProviderAttribute"/> class.
    /// </summary>
    /// <param name="providerType">
    /// The type that implements <see cref="IDefaultValidationComponentProvider"/>.
    /// Must have a parameterless constructor.
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="providerType"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="providerType"/> does not implement <see cref="IDefaultValidationComponentProvider"/>.
    /// </exception>
    public DefaultValidationComponentProviderAttribute(Type providerType)
    {
        if (providerType == null)
        {
            throw new ArgumentNullException(nameof(providerType));
        }

        if (!typeof(IDefaultValidationComponentProvider).IsAssignableFrom(providerType))
        {
            throw new ArgumentException(
                string.Format(ClassStrings.ErrorTypeMustImplementInterface, providerType.FullName, nameof(IDefaultValidationComponentProvider)),
                nameof(providerType));
        }

        ProviderType = providerType;
    }
}
