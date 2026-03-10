// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Builder returned by <c>ConfigureCoseValidation</c> to enable staged configuration.
/// </summary>
/// <remarks>
/// This type exists primarily to gate extension-pack configuration behind an explicit
/// call to <c>ConfigureCoseValidation</c> so that trust-pack extension methods do not
/// pollute <see cref="IServiceCollection"/> IntelliSense by default.
/// </remarks>
public interface ICoseValidationBuilder
{
    /// <summary>
    /// Gets the underlying service collection.
    /// </summary>
    IServiceCollection Services { get; }
}
