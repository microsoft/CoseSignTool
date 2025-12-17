// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSign1.Abstractions;
using CoseSign1.Abstractions.Transparency;
using CoseSignTool.Abstractions;

namespace CoseSignTool.Tests.Plugins;

// These types exist solely to be loaded by PluginLoader in tests.
// See CommandBuilderTests for how the test assembly is copied/renamed to *.Plugin.dll.

public sealed class ThrowingGetExtensionsPlugin : IPlugin
{
    public string Name => "ThrowExt";
    public string Version => "1.0.0";
    public string Description => "Test plugin that throws from GetExtensions";

    public PluginExtensions GetExtensions()
    {
        throw new InvalidOperationException("boom");
    }

    public void RegisterCommands(Command rootCommand)
    {
    }

    public Task InitializeAsync(IDictionary<string, string>? configuration = null)
    {
        return Task.CompletedTask;
    }
}

public sealed class ThrowingProvidersPlugin : IPlugin
{
    public string Name => "ThrowProviders";
    public string Version => "1.0.0";
    public string Description => "Test plugin that throws while collecting providers";

    public PluginExtensions GetExtensions()
    {
        return new PluginExtensions(
            signingCommandProviders: Array.Empty<ISigningCommandProvider>(),
            verificationProviders: new ThrowingEnumerable<IVerificationProvider>(new InvalidOperationException("verification fail")),
            transparencyProviders: new ITransparencyProviderContributor[] { new FaultingTransparencyContributor() });
    }

    public void RegisterCommands(Command rootCommand)
    {
    }

    public Task InitializeAsync(IDictionary<string, string>? configuration = null)
    {
        return Task.CompletedTask;
    }

    private sealed class FaultingTransparencyContributor : ITransparencyProviderContributor
    {
        public string ProviderName => "Faulting";
        public string ProviderDescription => "Faulting contributor";

        public Task<ITransparencyProvider> CreateTransparencyProviderAsync(
            IDictionary<string, object?> options,
            CancellationToken cancellationToken = default)
        {
            return Task.FromException<ITransparencyProvider>(new InvalidOperationException("transparency fail"));
        }
    }
}

public sealed class ThrowingRegisterCommandsPlugin : IPlugin
{
    public string Name => "ThrowRegister";
    public string Version => "1.0.0";
    public string Description => "Test plugin that throws during RegisterCommands";

    public PluginExtensions GetExtensions()
    {
        return new PluginExtensions(
            signingCommandProviders: new ISigningCommandProvider[] { new MinimalSigningCommandProvider() },
            verificationProviders: Array.Empty<IVerificationProvider>(),
            transparencyProviders: Array.Empty<ITransparencyProviderContributor>());
    }

    public void RegisterCommands(Command rootCommand)
    {
        throw new InvalidOperationException("register fail");
    }

    public Task InitializeAsync(IDictionary<string, string>? configuration = null)
    {
        return Task.CompletedTask;
    }

    private sealed class MinimalSigningCommandProvider : ISigningCommandProvider
    {
        public string CommandName => "sign-test";
        public string CommandDescription => "Test signing command";
        public string ExampleUsage => "--example value";

        public void AddCommandOptions(Command command)
        {
        }

        public Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
        {
            return Task.FromException<ISigningService<SigningOptions>>(new NotImplementedException("Not needed for command building"));
        }

        public IDictionary<string, string> GetSigningMetadata() => new Dictionary<string, string>();
    }
}

internal sealed class ThrowingEnumerable<T> : IEnumerable<T>
{
    private readonly Exception Exception;

    public ThrowingEnumerable(Exception exception)
    {
        Exception = exception;
    }

    public IEnumerator<T> GetEnumerator() => throw Exception;

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
}
