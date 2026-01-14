// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.DependencyInjection;

using Microsoft.Extensions.DependencyInjection;

internal sealed class CoseValidationBuilder : ICoseValidationBuilder
{
    public CoseValidationBuilder(IServiceCollection services)
    {
        Services = services ?? throw new ArgumentNullException(nameof(services));
    }

    public IServiceCollection Services { get; }
}
