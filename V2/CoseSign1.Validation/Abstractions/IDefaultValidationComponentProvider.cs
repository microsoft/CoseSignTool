// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Abstractions;

using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;

/// <summary>
/// Interface for extension packages to provide default validation components
/// for auto-discovery when no explicit configuration is provided.
/// </summary>
/// <remarks>
/// <para>
/// Implement this interface in your extension package and mark it with
/// <see cref="DefaultValidationComponentProviderAttribute"/> at the assembly level
/// to have your components automatically discovered and used when callers invoke
/// <c>message.Validate()</c> without explicit configuration.
/// </para>
/// <para>
/// Example assembly attribute usage:
/// <code>
/// [assembly: DefaultValidationComponentProvider(typeof(MyCertificateComponentProvider))]
/// </code>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// public class MyCertificateComponentProvider : IDefaultValidationComponentProvider
/// {
///     public int Priority => 100;
///     
///     public IEnumerable&lt;IValidationComponent&gt; GetDefaultComponents(ILoggerFactory? loggerFactory)
///     {
///         yield return new CertificateSigningKeyResolver();
///         yield return new CertificateChainAssertionProvider();
///     }
/// }
/// </code>
/// </example>
public interface IDefaultValidationComponentProvider
{
    /// <summary>
    /// Gets the priority for component ordering. Lower values are processed first.
    /// </summary>
    /// <remarks>
    /// Suggested ranges:
    /// <list type="bullet">
    /// <item><description>0-99: Core/fundamental components (signing key resolvers)</description></item>
    /// <item><description>100-199: Certificate validation components</description></item>
    /// <item><description>200-299: Trust/transparency components (MST, CT logs)</description></item>
    /// <item><description>300+: Custom/application-specific components</description></item>
    /// </list>
    /// </remarks>
    int Priority { get; }

    /// <summary>
    /// Gets the default validation components provided by this package.
    /// </summary>
    /// <param name="loggerFactory">Optional logger factory for creating loggers in components.</param>
    /// <returns>The default validation components this package provides.</returns>
    IEnumerable<IValidationComponent> GetDefaultComponents(ILoggerFactory? loggerFactory);
}
