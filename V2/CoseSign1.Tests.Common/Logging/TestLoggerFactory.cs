// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Tests.Common.Logging;

using Microsoft.Extensions.Logging;

/// <summary>
/// A logger factory for tests that captures log entries for inspection.
/// Each test should create its own instance to ensure complete isolation.
/// </summary>
public sealed class TestLoggerFactory : ILoggerFactory
{
    private readonly List<TestLogEntry> _entries = [];
    private readonly object _lock = new();
    private readonly LogLevel _minimumLevel;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="TestLoggerFactory"/> class.
    /// </summary>
    /// <param name="minimumLevel">The minimum log level to capture. Default is Trace (capture all).</param>
    public TestLoggerFactory(LogLevel minimumLevel = LogLevel.Trace)
    {
        _minimumLevel = minimumLevel;
    }

    /// <summary>
    /// Gets all captured log entries.
    /// </summary>
    public IReadOnlyList<TestLogEntry> Entries
    {
        get
        {
            lock (_lock)
            {
                return _entries.ToArray();
            }
        }
    }

    /// <summary>
    /// Gets log entries filtered by level.
    /// </summary>
    /// <param name="level">The log level to filter by.</param>
    /// <returns>Entries matching the specified level.</returns>
    public IEnumerable<TestLogEntry> GetEntriesAtLevel(LogLevel level)
    {
        lock (_lock)
        {
            return _entries.Where(e => e.Level == level).ToArray();
        }
    }

    /// <summary>
    /// Gets log entries containing the specified message substring.
    /// </summary>
    /// <param name="messageSubstring">The substring to search for in log messages.</param>
    /// <returns>Entries containing the substring.</returns>
    public IEnumerable<TestLogEntry> GetEntriesContaining(string messageSubstring)
    {
        ArgumentNullException.ThrowIfNull(messageSubstring);
        lock (_lock)
        {
            return _entries.Where(e => e.Message.Contains(messageSubstring, StringComparison.OrdinalIgnoreCase)).ToArray();
        }
    }

    /// <summary>
    /// Gets log entries for a specific category (logger name).
    /// </summary>
    /// <param name="categoryName">The category name to filter by.</param>
    /// <returns>Entries for the specified category.</returns>
    public IEnumerable<TestLogEntry> GetEntriesForCategory(string categoryName)
    {
        ArgumentNullException.ThrowIfNull(categoryName);
        lock (_lock)
        {
            return _entries.Where(e => e.CategoryName == categoryName).ToArray();
        }
    }

    /// <summary>
    /// Clears all captured log entries.
    /// </summary>
    public void Clear()
    {
        lock (_lock)
        {
            _entries.Clear();
        }
    }

    /// <inheritdoc/>
    public ILogger CreateLogger(string categoryName)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new TestLogger(categoryName, this, _minimumLevel);
    }

    /// <inheritdoc/>
    public void AddProvider(ILoggerProvider provider)
    {
        // No-op: This factory manages its own logging
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _disposed = true;
    }

    internal void AddEntry(TestLogEntry entry)
    {
        lock (_lock)
        {
            _entries.Add(entry);
        }
    }

    private sealed class TestLogger : ILogger
    {
        private readonly string _categoryName;
        private readonly TestLoggerFactory _factory;
        private readonly LogLevel _minimumLevel;

        public TestLogger(string categoryName, TestLoggerFactory factory, LogLevel minimumLevel)
        {
            _categoryName = categoryName;
            _factory = factory;
            _minimumLevel = minimumLevel;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            return NullScope.Instance;
        }

        public bool IsEnabled(LogLevel logLevel)
        {
            return logLevel >= _minimumLevel && logLevel != LogLevel.None;
        }

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var message = formatter(state, exception);
            var entry = new TestLogEntry(
                DateTimeOffset.UtcNow,
                logLevel,
                _categoryName,
                eventId,
                message,
                exception);

            _factory.AddEntry(entry);
        }

        private sealed class NullScope : IDisposable
        {
            public static NullScope Instance { get; } = new();
            public void Dispose() { }
        }
    }
}

/// <summary>
/// Represents a captured log entry.
/// </summary>
/// <param name="Timestamp">The time the log entry was created.</param>
/// <param name="Level">The log level.</param>
/// <param name="CategoryName">The logger category name.</param>
/// <param name="EventId">The event ID.</param>
/// <param name="Message">The formatted log message.</param>
/// <param name="Exception">The exception, if any.</param>
public sealed record TestLogEntry(
    DateTimeOffset Timestamp,
    LogLevel Level,
    string CategoryName,
    EventId EventId,
    string Message,
    Exception? Exception);
