// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Commands.Builders;

using System.CommandLine;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSignTool.Abstractions;
using CoseSignTool.Commands.Builders;
using CoseSignTool.Output;
using Microsoft.Extensions.Logging;

[TestFixture]
public class SigningCommandBuilderTests
{
    private sealed class TestSigningService : ISigningService<SigningOptions>
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public CoseSigner GetCoseSigner(SigningContext context)
        {
            return new CoseSigner(_key, HashAlgorithmName.SHA256);
        }

        public SigningOptions CreateSigningOptions() => new();

        public bool IsRemote => false;

        public SigningServiceMetadata ServiceMetadata { get; } = new("TestSigningService");

        public void Dispose()
        {
            _key.Dispose();
        }
    }

    private sealed class TestSigningCommandProvider : ISigningCommandProvider
    {
        private readonly Option<string> _modeOption = new("--mode", getDefaultValue: () => "success");

        public IDictionary<string, object?>? LastOptions { get; private set; }

        public string CommandName => "sign-test";

        public string CommandDescription => "Test signing command";

        public string ExampleUsage => "--mode success";

        public void AddCommandOptions(Command command)
        {
            command.AddOption(_modeOption);
        }

        public Task<ISigningService<SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
        {
            LastOptions = new Dictionary<string, object?>(options);

            var mode = options.TryGetValue("mode", out var value) ? value?.ToString() : "success";
            return mode switch
            {
                "throw-file" => throw new FileNotFoundException("missing dependency"),
                "throw-cancel" => throw new OperationCanceledException("timeout"),
                "throw-generic" => throw new InvalidOperationException("boom"),
                _ => Task.FromResult<ISigningService<SigningOptions>>(new TestSigningService())
            };
        }

        public IDictionary<string, string> GetSigningMetadata()
        {
            return new Dictionary<string, string>
            {
                ["TestMetadata"] = "Value"
            };
        }
    }

    private static RootCommand CreateRoot(Command signingCommand)
    {
        var root = new RootCommand("root");

        // Matches SigningCommandBuilder's lookup logic (option.Name == "output-format")
        var outputFormatOption = new Option<OutputFormat>("--output-format", getDefaultValue: () => OutputFormat.Quiet);
        root.AddOption(outputFormatOption);

        root.AddCommand(signingCommand);
        return root;
    }

    [Test]
    public async Task InvokeAsync_WhenPayloadFileMissing_Returns3()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var builder = new SigningCommandBuilder(new TestConsole(), transparencyProviders: null, loggerFactory: loggerFactory);
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var missingPayload = Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid():N}.bin");

        // Act
        var exitCode = await root.InvokeAsync(new[]
        {
            "--output-format", "quiet",
            provider.CommandName,
            missingPayload,
            "--quiet"
        });

        // Assert
        Assert.That(exitCode, Is.EqualTo(3));
    }

    [Test]
    public async Task InvokeAsync_WhenPayloadFileMissing_AndNotQuiet_Returns3()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        var builder = TestConsole.CreateSigningCommandBuilder();
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var missingPayload = Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid():N}.bin");

        // Act
        var exitCode = await root.InvokeAsync(new[]
        {
            "--output-format", "quiet",
            provider.CommandName,
            missingPayload,
            "--mode", "success"
        });

        // Assert
        Assert.That(exitCode, Is.EqualTo(3));
    }

    [Test]
    public async Task InvokeAsync_WithDetachedSignature_WritesOutputFileAndReturns0()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var builder = new SigningCommandBuilder(new TestConsole(), transparencyProviders: null, loggerFactory: loggerFactory);
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var tempDir = Path.Combine(Path.GetTempPath(), $"sign_builder_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var payloadPath = Path.Combine(tempDir, "payload.bin");
        await File.WriteAllBytesAsync(payloadPath, [0x01, 0x02, 0x03, 0x04]);

        var outputPath = Path.Combine(tempDir, "signature.cose");

        // Act
        var exitCode = await root.InvokeAsync(new[]
        {
            "--output-format", "quiet",
            provider.CommandName,
            payloadPath,
            "--signature-type", "detached",
            "--output", outputPath,
            "--content-type", "application/octet-stream",
            "--mode", "success",
            "--quiet"
        });

        // Assert
        Assert.That(exitCode, Is.EqualTo(0));
        Assert.That(File.Exists(outputPath), Is.True);
        Assert.That(new FileInfo(outputPath).Length, Is.GreaterThan(0));

        Assert.That(provider.LastOptions, Is.Not.Null);
        Assert.That(provider.LastOptions!.ContainsKey("mode"), Is.True);
        Assert.That(provider.LastOptions.ContainsKey("__loggerFactory"), Is.True);
    }

    [Test]
    public async Task InvokeAsync_WhenOutputNotSpecified_UsesDefaultOutputPathAndSkipsStandardOptions()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        var builder = TestConsole.CreateSigningCommandBuilder();
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var tempDir = Path.Combine(Path.GetTempPath(), $"sign_builder_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var payloadPath = Path.Combine(tempDir, "payload.bin");
        await File.WriteAllBytesAsync(payloadPath, [0x01, 0x02, 0x03, 0x04]);

        var defaultOutputPath = $"{payloadPath}.cose";

        try
        {
            // Act
            var exitCode = await root.InvokeAsync(new[]
            {
                "--output-format", "quiet",
                provider.CommandName,
                payloadPath,
                "--mode", "success"
            });

            // Assert
            Assert.That(exitCode, Is.EqualTo(0));
            Assert.That(File.Exists(defaultOutputPath), Is.True);
            Assert.That(new FileInfo(defaultOutputPath).Length, Is.GreaterThan(0));

            Assert.That(provider.LastOptions, Is.Not.Null);
            Assert.That(provider.LastOptions!.ContainsKey("mode"), Is.True);
            Assert.That(provider.LastOptions.ContainsKey("output"), Is.False);
            Assert.That(provider.LastOptions.ContainsKey("signature-type"), Is.False);
            Assert.That(provider.LastOptions.ContainsKey("content-type"), Is.False);
            Assert.That(provider.LastOptions.ContainsKey("quiet"), Is.False);
            Assert.That(provider.LastOptions.ContainsKey("__loggerFactory"), Is.False);
        }
        finally
        {
            if (File.Exists(defaultOutputPath))
            {
                File.Delete(defaultOutputPath);
            }
        }
    }

    [Test]
    public async Task InvokeAsync_WithEmbeddedSignatureAndLargePayload_WritesOutputFileAndReturns0()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        var builder = TestConsole.CreateSigningCommandBuilder();
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var tempDir = Path.Combine(Path.GetTempPath(), $"sign_builder_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var payloadPath = Path.Combine(tempDir, "large-payload.bin");
        var largePayload = new byte[200_000];
        RandomNumberGenerator.Fill(largePayload);
        await File.WriteAllBytesAsync(payloadPath, largePayload);

        var outputPath = Path.Combine(tempDir, "signature-embedded.cose");

        // Act
        var exitCode = await root.InvokeAsync(new[]
        {
            "--output-format", "quiet",
            provider.CommandName,
            payloadPath,
            "--signature-type", "embedded",
            "--output", outputPath,
            "--mode", "success"
        });

        // Assert
        Assert.That(exitCode, Is.EqualTo(0));
        Assert.That(File.Exists(outputPath), Is.True);
        Assert.That(new FileInfo(outputPath).Length, Is.GreaterThan(65_536));
    }

    [Test]
    public async Task InvokeAsync_WithIndirectSignature_WritesOutputFileAndReturns0()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        var builder = TestConsole.CreateSigningCommandBuilder();
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var tempDir = Path.Combine(Path.GetTempPath(), $"sign_builder_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var payloadPath = Path.Combine(tempDir, "payload.txt");
        await File.WriteAllTextAsync(payloadPath, "hello");

        var outputPath = Path.Combine(tempDir, "signature-indirect.cose");

        // Act
        var exitCode = await root.InvokeAsync(new[]
        {
            "--output-format", "quiet",
            provider.CommandName,
            payloadPath,
            "--signature-type", "indirect",
            "--output", outputPath,
            "--content-type", "text/plain",
            "--mode", "success",
            "--quiet"
        });

        // Assert
        Assert.That(exitCode, Is.EqualTo(0));
        Assert.That(File.Exists(outputPath), Is.True);
        Assert.That(new FileInfo(outputPath).Length, Is.GreaterThan(0));
    }

    [Test]
    public async Task InvokeAsync_WhenProviderThrowsFileNotFound_Returns3()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        var builder = TestConsole.CreateSigningCommandBuilder();
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var tempDir = Path.Combine(Path.GetTempPath(), $"sign_builder_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var payloadPath = Path.Combine(tempDir, "payload.bin");
        await File.WriteAllBytesAsync(payloadPath, [0x01]);

        // Act
        var exitCode = await root.InvokeAsync(new[]
        {
            "--output-format", "quiet",
            provider.CommandName,
            payloadPath,
            "--mode", "throw-file",
            "--quiet"
        });

        // Assert
        Assert.That(exitCode, Is.EqualTo(3));
    }

    [Test]
    public async Task InvokeAsync_WhenProviderThrowsFileNotFound_AndNotQuiet_Returns3()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        var builder = TestConsole.CreateSigningCommandBuilder();
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var tempDir = Path.Combine(Path.GetTempPath(), $"sign_builder_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var payloadPath = Path.Combine(tempDir, "payload.bin");
        await File.WriteAllBytesAsync(payloadPath, [0x01]);

        var outputPath = Path.Combine(tempDir, "signature.cose");

        try
        {
            // Act
            var exitCode = await root.InvokeAsync(new[]
            {
                "--output-format", "quiet",
                provider.CommandName,
                payloadPath,
                "--output", outputPath,
                "--mode", "throw-file"
            });

            // Assert
            Assert.That(exitCode, Is.EqualTo(3));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public async Task InvokeAsync_WhenProviderThrowsOperationCanceled_Returns11()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        var builder = TestConsole.CreateSigningCommandBuilder();
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var tempDir = Path.Combine(Path.GetTempPath(), $"sign_builder_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var payloadPath = Path.Combine(tempDir, "payload.bin");
        await File.WriteAllBytesAsync(payloadPath, [0x01]);

        // Act
        var exitCode = await root.InvokeAsync(new[]
        {
            "--output-format", "quiet",
            provider.CommandName,
            payloadPath,
            "--mode", "throw-cancel",
            "--quiet"
        });

        // Assert
        Assert.That(exitCode, Is.EqualTo(11));
    }

    [Test]
    public async Task InvokeAsync_WhenProviderThrowsOperationCanceled_AndNotQuiet_Returns11()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        var builder = TestConsole.CreateSigningCommandBuilder();
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var tempDir = Path.Combine(Path.GetTempPath(), $"sign_builder_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var payloadPath = Path.Combine(tempDir, "payload.bin");
        await File.WriteAllBytesAsync(payloadPath, [0x01]);

        var outputPath = Path.Combine(tempDir, "signature.cose");

        try
        {
            // Act
            var exitCode = await root.InvokeAsync(new[]
            {
                "--output-format", "quiet",
                provider.CommandName,
                payloadPath,
                "--output", outputPath,
                "--mode", "throw-cancel"
            });

            // Assert
            Assert.That(exitCode, Is.EqualTo(11));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public async Task InvokeAsync_WhenProviderThrowsGenericException_AndNotQuiet_Returns10()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        var builder = TestConsole.CreateSigningCommandBuilder();
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var tempDir = Path.Combine(Path.GetTempPath(), $"sign_builder_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var payloadPath = Path.Combine(tempDir, "payload.bin");
        await File.WriteAllBytesAsync(payloadPath, [0x01]);

        var outputPath = Path.Combine(tempDir, "signature.cose");

        try
        {
            // Act
            var exitCode = await root.InvokeAsync(new[]
            {
                "--output-format", "quiet",
                provider.CommandName,
                payloadPath,
                "--output", outputPath,
                "--mode", "throw-generic"
            });

            // Assert
            Assert.That(exitCode, Is.EqualTo(10));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public async Task InvokeAsync_WithNonQuietOutput_WritesSectionAndReturns0()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        var console = new TestConsole();
        var builder = new SigningCommandBuilder(console);
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var tempDir = Path.Combine(Path.GetTempPath(), $"sign_builder_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var payloadPath = Path.Combine(tempDir, "payload.bin");
        await File.WriteAllBytesAsync(payloadPath, [0x01, 0x02, 0x03]);

        var outputPath = Path.Combine(tempDir, "signature.cose");

        try
        {
            // Act
            var exitCode = await root.InvokeAsync(new[]
            {
                "--output-format", "text",
                provider.CommandName,
                payloadPath,
                "--signature-type", "detached",
                "--output", outputPath,
                "--mode", "success"
            });

            // Assert
            Assert.That(exitCode, Is.EqualTo(0));
            Assert.That(File.Exists(outputPath), Is.True);
            Assert.That(console.GetStdout(), Does.Contain("Signing Operation"));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public async Task InvokeAsync_WithOutputDash_WritesToStdoutAndReturns0()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        var builder = new SigningCommandBuilder(new TestConsole());
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var tempDir = Path.Combine(Path.GetTempPath(), $"sign_builder_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var payloadPath = Path.Combine(tempDir, "payload.bin");
        await File.WriteAllBytesAsync(payloadPath, [0x01, 0x02, 0x03, 0x04]);

        try
        {
            // Act
            var exitCode = await root.InvokeAsync(new[]
            {
                "--output-format", "quiet",
                provider.CommandName,
                payloadPath,
                "--signature-type", "detached",
                "--output", "-",
                "--mode", "success",
                "--quiet"
            });

            // Assert
            Assert.That(exitCode, Is.EqualTo(0));
        }
        finally
        {
            if (File.Exists(payloadPath))
            {
                File.Delete(payloadPath);
            }
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Test]
    public async Task InvokeAsync_WithLargePayloadAndEmbeddedSignature_WritesOutputFileAndReturns0()
    {
        // Arrange
        var provider = new TestSigningCommandProvider();
        var builder = TestConsole.CreateSigningCommandBuilder();
        var signingCommand = builder.BuildSigningCommand(provider);
        var root = CreateRoot(signingCommand);

        var tempDir = Path.Combine(Path.GetTempPath(), $"sign_builder_large_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        var payloadPath = Path.Combine(tempDir, "payload-large.bin");
        var payloadBytes = new byte[120_000]; // > 64KB to force multiple chunk writes
        RandomNumberGenerator.Fill(payloadBytes);
        await File.WriteAllBytesAsync(payloadPath, payloadBytes);

        var outputPath = Path.Combine(tempDir, "signature-large.cose");

        try
        {
            // Act
            var exitCode = await root.InvokeAsync(new[]
            {
                "--output-format", "quiet",
                provider.CommandName,
                payloadPath,
                "--signature-type", "embedded",
                "--output", outputPath,
                "--mode", "success",
                "--quiet"
            });

            // Assert
            Assert.That(exitCode, Is.EqualTo(0));
            Assert.That(File.Exists(outputPath), Is.True);
            Assert.That(new FileInfo(outputPath).Length, Is.GreaterThan(0));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }
}
