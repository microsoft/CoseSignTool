// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Direct;
using CoseSign1.Tests.Common;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using CoseSign1.Validation.Validators;

[TestFixture]
public class CompositeValidatorAdditionalTests
{
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    private static CoseSign1Message CreateValidMessage()
    {
        using var cert = TestCertificateUtils.CreateCertificate("CompositeAdditionalTest");
        var chainBuilder = new X509ChainBuilder();
        var signingService = CertificateSigningService.Create(cert, chainBuilder);
        var factory = new DirectSignatureFactory(signingService);
        var payload = new byte[] { 1, 2, 3, 4, 5 };
        var messageBytes = factory.CreateCoseSign1MessageBytes(payload, "application/test");
        return CoseSign1Message.DecodeSign1(messageBytes);
    }

    [Test]
    public async Task ValidateAsync_WithNullInput_ReturnsFailure()
    {
        var validators = new List<IValidator> { new MockValidator(true) };
        var composite = new CompositeValidator(validators);

        var result = await composite.ValidateAsync(null!, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Any(f => f.ErrorCode == "NULL_INPUT"), Is.True);
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task ValidateAsync_WithEmptyValidators_ReturnsSuccess()
    {
        var validMessage = CreateValidMessage();
        var composite = new CompositeValidator(new List<IValidator>());

        var result = await composite.ValidateAsync(validMessage, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task ValidateAsync_WithParallelExecution_RunsInParallel()
    {
        var validMessage = CreateValidMessage();
        var probe = new ConcurrencyProbe();
        var validators = new List<IValidator>
        {
            new ConcurrencyTrackingValidator(probe),
            new ConcurrencyTrackingValidator(probe),
            new ConcurrencyTrackingValidator(probe)
        };
        var composite = new CompositeValidator(validators, runInParallel: true);

        var validateTask = composite.ValidateAsync(validMessage, ValidationStage.Signature);

        // If running in parallel, multiple validators should start before we release them.
        await probe.StartedAtLeastTwoTask.WaitAsync(TimeSpan.FromSeconds(5));
        probe.Release.TrySetResult();

        var result = await validateTask;
        Assert.That(result.IsValid, Is.True);
        Assert.That(probe.MaxConcurrency, Is.GreaterThanOrEqualTo(2));
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task ValidateAsync_WithSequentialExecution_RunsSequentially()
    {
        var validMessage = CreateValidMessage();
        var validators = new List<IValidator>
        {
            new DelayedValidator(50, true),
            new DelayedValidator(50, true)
        };
        var composite = new CompositeValidator(validators, runInParallel: false);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await composite.ValidateAsync(validMessage, ValidationStage.Signature);
        sw.Stop();

        Assert.That(result.IsValid, Is.True);
        // Sequential should take at least 100ms
        Assert.That(sw.ElapsedMilliseconds, Is.GreaterThanOrEqualTo(90));
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task ValidateAsync_WithParallelAndFailure_CollectsAllFailures()
    {
        var validMessage = CreateValidMessage();
        var validators = new List<IValidator>
        {
            new MockValidator(false, "Error1"),
            new MockValidator(false, "Error2"),
            new MockValidator(false, "Error3")
        };
        var composite = new CompositeValidator(validators, runInParallel: true);

        var result = await composite.ValidateAsync(validMessage, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Failures.Count, Is.EqualTo(3));
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task ValidateAsync_WithStopOnFirstFailure_StopsAfterFirstFailure()
    {
        var validMessage = CreateValidMessage();
        var validator1 = new MockValidator(true);
        var validator2 = new MockValidator(false);
        var validator3 = new MockValidator(true);

        var validators = new List<IValidator> { validator1, validator2, validator3 };
        var composite = new CompositeValidator(validators, stopOnFirstFailure: true);

        var result = await composite.ValidateAsync(validMessage, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(validator1.WasCalled, Is.True);
        Assert.That(validator2.WasCalled, Is.True);
        Assert.That(validator3.WasCalled, Is.False);
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task ValidateAsync_WithoutStopOnFirstFailure_RunsAllValidators()
    {
        var validMessage = CreateValidMessage();
        var validator1 = new MockValidator(false);
        var validator2 = new MockValidator(false);
        var validator3 = new MockValidator(true);

        var validators = new List<IValidator> { validator1, validator2, validator3 };
        var composite = new CompositeValidator(validators, stopOnFirstFailure: false);

        var result = await composite.ValidateAsync(validMessage, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.False);
        Assert.That(validator1.WasCalled, Is.True);
        Assert.That(validator2.WasCalled, Is.True);
        Assert.That(validator3.WasCalled, Is.True);
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public async Task ValidateAsync_MergesMetadataFromSuccessfulValidators()
    {
        var validMessage = CreateValidMessage();
        var validator1 = new MockValidator(true, metadata: new Dictionary<string, object> { ["Data1"] = "Value1" });
        var validator2 = new MockValidator(true, metadata: new Dictionary<string, object> { ["Data2"] = "Value2" });

        var validators = new List<IValidator> { validator1, validator2 };
        var composite = new CompositeValidator(validators);

        var result = await composite.ValidateAsync(validMessage, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata.ContainsKey("MockValidator.Data1"), Is.True);
        Assert.That(result.Metadata.ContainsKey("MockValidator.Data2"), Is.True);
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public void Validate_WithMetadataConflicts_NamespacesWithValidatorName()
    {
        var validMessage = CreateValidMessage();
        var validator1 = new MockValidator(true, "V1", new Dictionary<string, object> { ["Key"] = "Value1" });
        var validator2 = new MockValidator(true, "V2", new Dictionary<string, object> { ["Key"] = "Value2" });

        var validators = new List<IValidator> { validator1, validator2 };
        var composite = new CompositeValidator(validators);

        var result = composite.Validate(validMessage, ValidationStage.Signature);

        Assert.That(result.IsValid, Is.True);
        Assert.That(result.Metadata["MockValidator_V1.Key"], Is.EqualTo("Value1"));
        Assert.That(result.Metadata["MockValidator_V2.Key"], Is.EqualTo("Value2"));
    }

    [Test]
    [System.Runtime.Versioning.RequiresPreviewFeatures("Uses preview cryptography APIs.")]
    public void ValidateAsync_WithCancellationRequested_ThrowsTaskCanceledException()
    {
        var validMessage = CreateValidMessage();
        var validator = new CancellableValidator();
        var composite = new CompositeValidator(new List<IValidator> { validator });
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.ThrowsAsync<TaskCanceledException>(() => composite.ValidateAsync(validMessage, ValidationStage.Signature, cts.Token));
    }

    // Mock validators for testing
    private class MockValidator : IValidator
    {
        private readonly bool ShouldPass;
        private readonly string ErrorMessage;
        private readonly Dictionary<string, object>? Metadata;
        private readonly string ValidatorName;
        public bool WasCalled { get; private set; }

        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

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

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
        {
            WasCalled = true;

            if (ShouldPass)
            {
                return ValidationResult.Success(ValidatorName, Metadata);
            }

            return ValidationResult.Failure(ValidatorName, ErrorMessage, "MOCK_ERROR");
        }

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Validate(input, stage));
        }
    }

    private class DelayedValidator : IValidator
    {
        private readonly int DelayMs;
        private readonly bool ShouldPass;

        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

        public DelayedValidator(int delayMs, bool shouldPass)
        {
            DelayMs = delayMs;
            ShouldPass = shouldPass;
        }

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
        {
            Thread.Sleep(DelayMs);
            return ShouldPass
                ? ValidationResult.Success("DelayedValidator")
                : ValidationResult.Failure("DelayedValidator", "Delayed error", "DELAY_ERROR");
        }

        public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
        {
            await Task.Delay(DelayMs, cancellationToken);
            return ShouldPass
                ? ValidationResult.Success("DelayedValidator")
                : ValidationResult.Failure("DelayedValidator", "Delayed error", "DELAY_ERROR");
        }
    }

    private class CancellableValidator : IValidator
    {
        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
        {
            return ValidationResult.Success("CancellableValidator");
        }

        public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
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

    private sealed class ConcurrencyTrackingValidator : IValidator
    {
        private readonly ConcurrencyProbe Probe;

        public IReadOnlyCollection<ValidationStage> Stages { get; } = new[] { ValidationStage.Signature };

        public ConcurrencyTrackingValidator(ConcurrencyProbe probe)
        {
            Probe = probe;
        }

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
        {
            throw new NotSupportedException("Use ValidateAsync for this validator.");
        }

        public async Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
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