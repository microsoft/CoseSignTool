// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.DependencyInjection;

using CoseSign1.Abstractions;
using Microsoft.Extensions.DependencyInjection;

internal sealed class CoseValidationBuilder : ICoseValidationBuilder
{
    public CoseValidationBuilder(IServiceCollection services)
    {
        Guard.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }
}
