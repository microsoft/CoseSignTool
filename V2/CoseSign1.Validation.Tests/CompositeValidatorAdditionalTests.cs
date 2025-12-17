// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Local;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation;
using NUnit.Framework;

namespace CoseSign1.Validation.Tests;

[TestFixture]
public class CompositeValidatorAdditionalTests
{
    private CoseSign1Message? ValidMessage;

    [SetUp]
#pragma warning disable CA2252
    public void SetUp()
    {
        var cert = TestCertificateUtils.CreateCertificate("CompositeAdditionalTest");
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        ValidMessage = CoseSign1Message.DecodeSign1(messageBytes);
        cert.Dispose();
    }
#pragma warning restore CA2252

    [Test]
    public async Task ValidateAsync_WithNullInput_ReturnsFailure()
    {
        var validators = new List<IValidator<CoseSign1Message>> { new MockValidator(true) };
        var composite = new CompositeValidator(validators);

        var result = await composite.ValidateAsync(null!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithEmptyValidators_ReturnsSuccess()
    {
        var composite = new CompositeValidator(new List<IValidator<CoseSign1Message>>());

        var result = await composite.ValidateAsync(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    public async Task ValidateAsync_WithParallelExecution_RunsInParallel()
    {
        var probe = new ConcurrencyProbe();
        var validators = new List<IValidator<CoseSign1Message>>
        {
            new ConcurrencyTrackingValidator(probe),
            new ConcurrencyTrackingValidator(probe),
            new ConcurrencyTrackingValidator(probe)
        };
        var composite = new CompositeValidator(validators, runInParallel: true);

        var validateTask = composite.ValidateAsync(ValidMessage!);

        // If running in parallel, multiple validators should start before we release them.
        await probe.StartedAtLeastTwoTask.WaitAsync(TimeSpan.FromSeconds(5));
        probe.Release.TrySetResult();

        var result = await validateTask;
        Assert.That(result.IsValid, Is.True);
        Assert.That(probe.MaxConcurrency, Is.GreaterThanOrEqualTo(2));
    }

    [Test]
    public async Task ValidateAsync_WithSequentialExecution_RunsSequentially()
    {
        var validators = new List<IValidator<CoseSign1Message>>
        {
            new DelayedValidator(50, true),
            new DelayedValidator(50, true)
        };
        var composite = new CompositeValidator(validators, runInParallel: false);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await composite.ValidateAsync(ValidMessage!);
        sw.Stop();

        Assert.That(result.IsValid, Is.True);
        // Sequential should take at least 100ms
        Assert.That(sw.ElapsedMilliseconds, Is.GreaterThanOrEqualTo(90));
    }

    [Test]
    public async Task ValidateAsync_WithParallelAndFailure_CollectsAllFailures()
    {
        var validators = new List<IValidator<CoseSign1Message>>
        {
            new MockValidator(false, "Error1"),
            new MockValidator(false, "Error2"),
            new MockValidator(false, "Error3")
        };
        var composite = new CompositeValidator(validators, runInParallel: true);

        var result = await composite.ValidateAsync(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Count, Is.EqualTo(3));
    }

    [Test]
    public async Task ValidateAsync_WithStopOnFirstFailure_StopsAfterFirstFailure()
    {
        var validator1 = new MockValidator(true);
        var validator2 = new MockValidator(false);
        var validator3 = new MockValidator(true);

        var validators = new List<IValidator<CoseSign1Message>> { validator1, validator2, validator3 };
        var composite = new CompositeValidator(validators, stopOnFirstFailure: true);

        var result = await composite.ValidateAsync(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(validator1.WasCalled, Is.True);
        Assert.That(validator2.WasCalled, Is.True);
        Assert.That(validator3.WasCalled, Is.False);
    }

    [Test]
    public async Task ValidateAsync_WithoutStopOnFirstFailure_RunsAllValidators()
    {
        var validator1 = new MockValidator(false);
        var validator2 = new MockValidator(false);
        var validator3 = new MockValidator(true);

        var validators = new List<IValidator<CoseSign1Message>> { validator1, validator2, validator3 };
        var composite = new CompositeValidator(validators, stopOnFirstFailure: false);

        var result = await composite.ValidateAsync(ValidMessage!);

        Assert.That(result.IsValid, Is.False);
        Assert.That(validator1.WasCalled, Is.True);
        Assert.That(validator2.WasCalled, Is.True);
        Assert.That(validator3.WasCalled, Is.True);
    }

    [Test]
    public async Task ValidateAsync_MergesMetadataFromSuccessfulValidators()
    {
        var validator1 = new MockValidator(true, metadata: new Dictionary<string, object> { ["Data1"] = "Value1" });
        var validator2 = new MockValidator(true, metadata: new Dictionary<string, object> { ["Data2"] = "Value2" });

        var validators = new List<IValidator<CoseSign1Message>> { validator1, validator2 };
        var composite = new CompositeValidator(validators);

        var result = await composite.ValidateAsync(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.ContainsKey("MockValidator.Data1"), Is.True);
        Assert.That(result.Metadata.ContainsKey("MockValidator.Data2"), Is.True);
    }

    [Test]
    public void Validate_WithMetadataConflicts_NamespacesWithValidatorName()
    {
        var validator1 = new MockValidator(true, "V1", new Dictionary<string, object> { ["Key"] = "Value1" });
        var validator2 = new MockValidator(true, "V2", new Dictionary<string, object> { ["Key"] = "Value2" });

        var validators = new List<IValidator<CoseSign1Message>> { validator1, validator2 };
        var composite = new CompositeValidator(validators);

        var result = composite.Validate(ValidMessage!);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["MockValidator_V1.Key"], Is.EqualTo("Value1"));
        Assert.That(result.Metadata["MockValidator_V2.Key"], Is.EqualTo("Value2"));
    }

    [Test]
    public void ValidateAsync_WithCancellationRequested_ThrowsTaskCanceledException()
    {
        var validator = new CancellableValidator();
        var composite = new CompositeValidator(new List<IValidator<CoseSign1Message>> { validator });
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.ThrowsAsync<TaskCanceledException>(() => composite.ValidateAsync(ValidMessage!, cts.Token));
    }

    // Mock validators for testing
    private class MockValidator : IValidator<CoseSign1Message>
    {
        private readonly bool ShouldPass;
        private readonly string ErrorMessage;
        private readonly Dictionary<string, object>? Metadata;
        private readonly string ValidatorName;
        public bool WasCalled { get; private set; }

        public MockValidator(bool shouldPass, string? errorMessageOrSuffix = null, Dictionary<string, object>? metadata = null)
        {
            ShouldPass = shouldPass;
            Metadata = metadata;

            // If metadata is provided and errorMessageOrSuffix doesn't contain "error", treat it as a suffix
            if (metadata != null && errorMessageOrSuffix != null && !errorMessageOrSuffix.ToLowerInvariant().Contains("error"))
            {
                ValidatorName = $"MockValidator_{errorMessageOrSuffix}";
                ErrorMessage = "Mock error";
            }
            else
            {
                ValidatorName = "MockValidator";
                ErrorMessage = errorMessageOrSuffix ?? "Mock error";
            }
        }

        public ValidationResult Validate(CoseSign1Message input)
        {
            WasCalled = true;

            if (ShouldPass)
            {
                return ValidationResult.Success(ValidatorName, Metadata);
            }

            return ValidationResult.Failure(ValidatorName, ErrorMessage, "MOCK_ERROR");
        }

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Validate(input));
        }
    }

    private class DelayedValidator : IValidator<CoseSign1Message>
    {
        private readonly int DelayMs;
        private readonly bool ShouldPass;

        public DelayedValidator(int delayMs, bool shouldPass)
        {
            DelayMs = delayMs;
            ShouldPass = shouldPass;
        }

        public ValidationResult Validate(CoseSign1Message input)
        {
            Thread.Sleep(DelayMs);
            return ShouldPass
                ? ValidationResult.Success("DelayedValidator")
                : ValidationResult.Failure("DelayedValidator", "Delayed error", "DELAY_ERROR");
        }

        public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
        {
            await Task.Delay(DelayMs, cancellationToken);
            return ShouldPass
                ? ValidationResult.Success("DelayedValidator")
                : ValidationResult.Failure("DelayedValidator", "Delayed error", "DELAY_ERROR");
        }
    }

    private class CancellableValidator : IValidator<CoseSign1Message>
    {
        public ValidationResult Validate(CoseSign1Message input)
        {
            return ValidationResult.Success("CancellableValidator");
        }

        public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
        {
            await Task.Delay(100, cancellationToken);
            return ValidationResult.Success("CancellableValidator");
        }
    }

    private sealed class ConcurrencyProbe
    {
        private int Current;
        private int StartedCount;
        private int Max;

        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private TaskCompletionSource StartedAtLeastTwo { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task StartedAtLeastTwoTask => StartedAtLeastTwo.Task;

        public int MaxConcurrency => Volatile.Read(ref Max);

        public void OnStart()
        {
            var now = Interlocked.Increment(ref Current);
            UpdateMax(now);

            if (Interlocked.Increment(ref StartedCount) >= 2)
            {
                StartedAtLeastTwo.TrySetResult();
            }
        }

        public void OnFinish()
        {
            Interlocked.Decrement(ref Current);
        }

        private void UpdateMax(int value)
        {
            while (true)
            {
                var snapshot = Volatile.Read(ref Max);
                if (value <= snapshot)
                {
                    return;
                }

                if (Interlocked.CompareExchange(ref Max, value, snapshot) == snapshot)
                {
                    return;
                }
            }
        }
    }

    private sealed class ConcurrencyTrackingValidator : IValidator<CoseSign1Message>
    {
        private readonly ConcurrencyProbe Probe;

        public ConcurrencyTrackingValidator(ConcurrencyProbe probe)
        {
            Probe = probe;
        }

        public ValidationResult Validate(CoseSign1Message input)
        {
            throw new NotSupportedException("Use ValidateAsync for this validator.");
        }

        public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
        {
            Probe.OnStart();
            try
            {
                await Probe.Release.Task.WaitAsync(cancellationToken);
                return ValidationResult.Success("ConcurrencyTrackingValidator");
            }
            finally
            {
                Probe.OnFinish();
            }
        }
    }
}