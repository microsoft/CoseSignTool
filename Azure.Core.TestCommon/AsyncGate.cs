// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Azure.Core.TestCommon;

/// <summary>
/// A gate for coordinating async operations in tests.
/// </summary>
[ExcludeFromCodeCoverage]
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
public class AsyncGate<TIn, TOut>
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);
    private readonly object _sync = new();
    private TaskCompletionSource<TIn> _signalTaskCompletionSource = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TaskCompletionSource<TOut> _releaseTaskCompletionSource = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>
    /// Waits for a signal with the default timeout.
    /// </summary>
    public Task<TIn> WaitForSignal()
    {
        return TimeoutAfter(_signalTaskCompletionSource.Task, DefaultTimeout);
    }

    /// <summary>
    /// Cycles through waiting for signal and releasing.
    /// </summary>
    public async Task<TIn> Cycle(TOut value = default!)
    {
        var signal = await WaitForSignal();
        Release(value);
        return signal;
    }

    /// <summary>
    /// Cycles through waiting for signal and releasing with an exception.
    /// </summary>
    public async Task<TIn> CycleWithException(Exception exception)
    {
        var signal = await WaitForSignal();
        ReleaseWithException(exception);
        return signal;
    }

    /// <summary>
    /// Releases the gate with a value.
    /// </summary>
    public void Release(TOut value = default!)
    {
        lock (_sync)
        {
            Reset().SetResult(value);
        }
    }

    /// <summary>
    /// Releases the gate with an exception.
    /// </summary>
    public void ReleaseWithException(Exception exception)
    {
        lock (_sync)
        {
            Reset().SetException(exception);
        }
    }

    private TaskCompletionSource<TOut> Reset()
    {
        lock (_sync)
        {
            if (!_signalTaskCompletionSource.Task.IsCompleted)
            {
                throw new InvalidOperationException("No await call to release");
            }

            var releaseTaskCompletionSource = _releaseTaskCompletionSource;
            _releaseTaskCompletionSource = new TaskCompletionSource<TOut>(TaskCreationOptions.RunContinuationsAsynchronously);
            _signalTaskCompletionSource = new TaskCompletionSource<TIn>(TaskCreationOptions.RunContinuationsAsynchronously);
            return releaseTaskCompletionSource;
        }
    }

    /// <summary>
    /// Waits for the gate to be released.
    /// </summary>
    public Task<TOut> WaitForRelease(TIn value = default!)
    {
        lock (_sync)
        {
            _signalTaskCompletionSource.SetResult(value);
            return TimeoutAfter(_releaseTaskCompletionSource.Task, DefaultTimeout);
        }
    }

    private static async Task<T> TimeoutAfter<T>(Task<T> task, TimeSpan timeout)
    {
        if (task.IsCompleted || Debugger.IsAttached)
        {
            return await task;
        }

        using var cts = new CancellationTokenSource();
        if (task == await Task.WhenAny(task, Task.Delay(timeout, cts.Token)))
        {
            await cts.CancelAsync();
            return await task;
        }

        throw new TimeoutException($"Operation timed out after {timeout}");
    }
}
#pragma warning restore CS1591
