// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using CoseSign1.Abstractions;
using CoseSign1.Abstractions.Transparency;
using CoseSignTool.Abstractions;

namespace CoseSignTool.TestPlugins.Plugin;

/// <summary>
/// Test plugin that throws from <see cref="IPlugin.GetExtensions"/>.
/// </summary>
public sealed class ThrowingGetExtensionsPlugin : IPlugin
{
    internal static class ClassStrings
    {
        public const string Name = "ThrowExt";
        public const string Version = "1.0.0";
        public const string Description = "Test plugin that throws from GetExtensions";
        public const string ErrorMessageBoom = "boom";
    }

    /// <inheritdoc/>
    public string Name => ClassStrings.Name;

    /// <inheritdoc/>
    public string Version => ClassStrings.Version;

    /// <inheritdoc/>
    public string Description => ClassStrings.Description;

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Always thrown for test coverage.</exception>
    public PluginExtensions GetExtensions() => throw new InvalidOperationException(ClassStrings.ErrorMessageBoom);

    /// <inheritdoc/>
    public void RegisterCommands(Command rootCommand)
    {
    }

    /// <inheritdoc/>
    public Task InitializeAsync(IDictionary<string, string>? configuration = null) => Task.CompletedTask;
}

/// <summary>
/// Test plugin that throws while enumerating verification/transparency providers.
/// </summary>
public sealed class ThrowingProvidersPlugin : IPlugin
{
    internal static class ClassStrings
    {
        public const string Name = "ThrowProviders";
        public const string Version = "1.0.0";
        public const string Description = "Test plugin that throws while collecting providers";
        public const string ErrorMessageVerificationFail = "verification fail";
    }

    /// <inheritdoc/>
    public string Name => ClassStrings.Name;

    /// <inheritdoc/>
    public string Version => ClassStrings.Version;

    /// <inheritdoc/>
    public string Description => ClassStrings.Description;

    /// <inheritdoc/>
    public PluginExtensions GetExtensions()
    {
        return new PluginExtensions(
            signingCommandProviders: Array.Empty<ISigningCommandProvider>(),
            verificationProviders: new ThrowingEnumerable<IVerificationProvider>(new InvalidOperationException(ClassStrings.ErrorMessageVerificationFail)),
            transparencyProviders: new ITransparencyProviderContributor[] { new FaultingTransparencyContributor() });
    }

    /// <inheritdoc/>
    public void RegisterCommands(Command rootCommand)
    {
    }

    /// <inheritdoc/>
    public Task InitializeAsync(IDictionary<string, string>? configuration = null) => Task.CompletedTask;

    private sealed class FaultingTransparencyContributor : ITransparencyProviderContributor
    {
        internal static class ClassStrings
        {
            public const string ProviderName = "Faulting";
            public const string ProviderDescription = "Faulting contributor";
            public const string ErrorMessageTransparencyFail = "transparency fail";
        }

        public string ProviderName => ClassStrings.ProviderName;
        public string ProviderDescription => ClassStrings.ProviderDescription;

        public Task<ITransparencyProvider> CreateTransparencyProviderAsync(
            IDictionary<string, object?> options,
            CancellationToken cancellationToken = default)
        {
            return Task.FromException<ITransparencyProvider>(new InvalidOperationException(ClassStrings.ErrorMessageTransparencyFail));
        }
    }
}

/// <summary>
/// Test plugin that throws during <see cref="IPlugin.RegisterCommands"/>.
/// </summary>
public sealed class ThrowingRegisterCommandsPlugin : IPlugin
{
    internal static class ClassStrings
    {
        public const string Name = "ThrowRegister";
        public const string Version = "1.0.0";
        public const string Description = "Test plugin that throws during RegisterCommands";
        public const string ErrorMessageRegisterFail = "register fail";
    }

    /// <inheritdoc/>
    public string Name => ClassStrings.Name;

    /// <inheritdoc/>
    public string Version => ClassStrings.Version;

    /// <inheritdoc/>
    public string Description => ClassStrings.Description;

    /// <inheritdoc/>
    public PluginExtensions GetExtensions()
    {
        return new PluginExtensions(
            signingCommandProviders: new ISigningCommandProvider[] { new MinimalSigningCommandProvider() },
            verificationProviders: Array.Empty<IVerificationProvider>(),
            transparencyProviders: Array.Empty<ITransparencyProviderContributor>());
    }

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">Always thrown for test coverage.</exception>
    public void RegisterCommands(Command rootCommand) => throw new InvalidOperationException(ClassStrings.ErrorMessageRegisterFail);

    /// <inheritdoc/>
    public Task InitializeAsync(IDictionary<string, string>? configuration = null) => Task.CompletedTask;

    private sealed class MinimalSigningCommandProvider : ISigningCommandProvider
    {
        internal static class ClassStrings
        {
            public const string CommandName = "sign-test";
            public const string CommandDescription = "Test signing command";
            public const string ExampleUsage = "--example value";
            public const string ErrorMessageNotNeededForCommandBuilding = "Not needed for command building";
        }

        public string CommandName => ClassStrings.CommandName;
        public string CommandDescription => ClassStrings.CommandDescription;
        public string ExampleUsage => ClassStrings.ExampleUsage;

        public void AddCommandOptions(Command command)
        {
        }

        public Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
        {
            return Task.FromException<ISigningService<SigningOptions>>(new NotImplementedException(ClassStrings.ErrorMessageNotNeededForCommandBuilding));
        }

        public IDictionary<string, string> GetSigningMetadata() => new Dictionary<string, string>();
    }
}

internal sealed class ThrowingEnumerable<T> : IEnumerable<T>
{
    private readonly Exception Exception;

    public ThrowingEnumerable(Exception exception) => Exception = exception;

    public IEnumerator<T> GetEnumerator() => throw Exception;

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
}
