// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.Extensions.DependencyInjection;

using CoseSign1.Validation.DependencyInjection;
using CoseSign1.Validation.Trust.Facts.Producers;

/// <summary>
/// Validation builder extensions for enabling core message-level facts.
/// </summary>
public static class MessageFactsValidationBuilderExtensions
{
    /// <summary>
    /// Enables core message-level fact production.
    /// </summary>
    /// <param name="validationBuilder">The validation builder.</param>
    /// <returns>The same builder instance for chaining.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="validationBuilder"/> is null.</exception>
    public static ICoseValidationBuilder EnableMessageFacts(this ICoseValidationBuilder validationBuilder)
    {
        if (validationBuilder == null)
        {
            throw new ArgumentNullException(nameof(validationBuilder));
        }

        var services = validationBuilder.Services;

        var alreadyAdded = false;
        foreach (var sd in services)
        {
            if (sd.ServiceType == typeof(ITrustPack) &&
                sd.ImplementationType == typeof(CoreMessageFactsProducer))
            {
                alreadyAdded = true;
                break;
            }
        }

        if (!alreadyAdded)
        {
            services.AddSingleton<ITrustPack, CoreMessageFactsProducer>();
        }

        return validationBuilder;
    }
}
