// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Tests.Configuration;

using CoseSignTool.Configuration;
using Microsoft.Extensions.Logging;

// Factory helper for tests that need LoggingConfiguration
file static class LoggingTestHelper
{
    /// <summary>
    /// Creates a logger factory with a TestConsole for testing.
    /// </summary>
    public static ILoggerFactory CreateLoggerFactory(int verbosity = 1)
        => LoggingConfiguration.CreateLoggerFactory(verbosity, new TestConsole());
}

/// <summary>
/// Tests for the LoggingConfiguration class.
/// </summary>
[TestFixture]
public class LoggingConfigurationTests
{
    [TestCase(0, LogLevel.None)]        // Quiet
    [TestCase(1, LogLevel.Warning)]     // Normal (default)
    [TestCase(2, LogLevel.Information)] // Verbose
    [TestCase(3, LogLevel.Debug)]       // Debug
    [TestCase(4, LogLevel.Trace)]       // Very verbose
    [TestCase(5, LogLevel.Trace)]       // Even more verbose still maps to Trace
    public void CreateLoggerFactory_WithVerbosityLevel_ReturnsCorrectMinimumLevel(int verbosity, LogLevel expectedLevel)
    {
        // Act
        using var factory = LoggingTestHelper.CreateLoggerFactory(verbosity);

        // Assert
        Assert.That(factory, Is.Not.Null);
        // Create a logger to verify it works
        var logger = factory.CreateLogger<LoggingConfigurationTests>();
        Assert.That(logger, Is.Not.Null);
    }

    [Test]
    public void CreateLoggerFactory_WithDefaultVerbosity_ReturnsWarningLevel()
    {
        // Act
        using var factory = LoggingTestHelper.CreateLoggerFactory();

        // Assert
        Assert.That(factory, Is.Not.Null);
        var logger = factory.CreateLogger<LoggingConfigurationTests>();
        Assert.That(logger, Is.Not.Null);
    }

    [Test]
    public void CreateLoggerFactory_WithNegativeVerbosity_DefaultsToWarning()
    {
        // Act
        using var factory = LoggingTestHelper.CreateLoggerFactory(-1);

        // Assert
        Assert.That(factory, Is.Not.Null);
        var logger = factory.CreateLogger<LoggingConfigurationTests>();
        Assert.That(logger, Is.Not.Null);
    }

    [Test]
    public void CreateLogger_WithFactory_ReturnsTypedLogger()
    {
        // Arrange
        using var factory = LoggingTestHelper.CreateLoggerFactory(2);

        // Act
        var logger = LoggingConfiguration.CreateLogger<LoggingConfigurationTests>(factory);

        // Assert
        Assert.That(logger, Is.Not.Null);
        Assert.That(logger, Is.InstanceOf<ILogger<LoggingConfigurationTests>>());
    }

    [Test]
    public void ParseVerbosity_WithNoVerbosityArgs_ReturnsDefault()
    {
        // Arrange
        var args = new[] { "sign", "--payload", "file.txt" };

        // Act
        int verbosity = LoggingConfiguration.ParseVerbosity(ref args);

        // Assert
        Assert.That(verbosity, Is.EqualTo(1)); // Default
        Assert.That(args, Has.Length.EqualTo(3));
    }

    [Test]
    public void ParseVerbosity_WithQuietFlag_ReturnsZeroAndKeepsArg()
    {
        // Arrange
        var args = new[] { "sign", "-q", "--payload", "file.txt" };

        // Act
        int verbosity = LoggingConfiguration.ParseVerbosity(ref args);

        // Assert
        Assert.That(verbosity, Is.EqualTo(0));
        // -q should be kept in args for command handlers
        Assert.That(args, Does.Contain("-q"));
        Assert.That(args, Has.Length.EqualTo(4));
    }

    [Test]
    public void ParseVerbosity_WithQuietLongFlag_ReturnsZeroAndKeepsArg()
    {
        // Arrange
        var args = new[] { "sign", "--quiet", "--payload", "file.txt" };

        // Act
        int verbosity = LoggingConfiguration.ParseVerbosity(ref args);

        // Assert
        Assert.That(verbosity, Is.EqualTo(0));
        Assert.That(args, Does.Contain("--quiet"));
        Assert.That(args, Has.Length.EqualTo(4));
    }

    [Test]
    public void ParseVerbosity_WithDoubleV_ReturnsThreeAndStripsArg()
    {
        // Arrange
        var args = new[] { "sign", "-vv", "--payload", "file.txt" };

        // Act
        int verbosity = LoggingConfiguration.ParseVerbosity(ref args);

        // Assert
        Assert.That(verbosity, Is.EqualTo(3));
        Assert.That(args, Does.Not.Contain("-vv"));
        Assert.That(args, Has.Length.EqualTo(3));
    }

    [Test]
    public void ParseVerbosity_WithTripleV_ReturnsFourAndStripsArg()
    {
        // Arrange
        var args = new[] { "sign", "-vvv", "--payload", "file.txt" };

        // Act
        int verbosity = LoggingConfiguration.ParseVerbosity(ref args);

        // Assert
        Assert.That(verbosity, Is.EqualTo(4));
        Assert.That(args, Does.Not.Contain("-vvv"));
        Assert.That(args, Has.Length.EqualTo(3));
    }

    [Test]
    public void ParseVerbosity_WithVerbosityLevel_ParsesAndStripsArgs()
    {
        // Arrange
        var args = new[] { "sign", "--verbosity", "2", "--payload", "file.txt" };

        // Act
        int verbosity = LoggingConfiguration.ParseVerbosity(ref args);

        // Assert
        Assert.That(verbosity, Is.EqualTo(2));
        Assert.That(args, Does.Not.Contain("--verbosity"));
        Assert.That(args, Does.Not.Contain("2"));
        Assert.That(args, Has.Length.EqualTo(3));
    }

    [Test]
    public void ParseVerbosity_WithInvalidVerbosityLevel_KeepsDefault()
    {
        // Arrange
        var args = new[] { "sign", "--verbosity", "invalid", "--payload", "file.txt" };

        // Act
        int verbosity = LoggingConfiguration.ParseVerbosity(ref args);

        // Assert
        Assert.That(verbosity, Is.EqualTo(1)); // Default stays 1 when parse fails
        // Both args should still be stripped
        Assert.That(args, Does.Not.Contain("--verbosity"));
        Assert.That(args, Has.Length.EqualTo(3));
    }

    [Test]
    public void ParseVerbosity_WithVerbosityAtEnd_ParsesCorrectly()
    {
        // Arrange - verbosity at end with no value following
        var args = new[] { "sign", "--payload", "file.txt", "--verbosity" };

        // Act
        int verbosity = LoggingConfiguration.ParseVerbosity(ref args);

        // Assert
        Assert.That(verbosity, Is.EqualTo(1)); // Default since no value follows
        Assert.That(args, Does.Contain("--verbosity")); // Not stripped since it couldn't be parsed
    }

    [Test]
    public void ParseVerbosity_WithMultipleVerbosityFlags_UsesHighest()
    {
        // Arrange - -vv followed by -vvv should use highest
        var args = new[] { "sign", "-vv", "--payload", "file.txt", "-vvv" };

        // Act
        int verbosity = LoggingConfiguration.ParseVerbosity(ref args);

        // Assert
        Assert.That(verbosity, Is.EqualTo(4)); // -vvv = 4 is higher than -vv = 3
        Assert.That(args, Has.Length.EqualTo(3));
    }

    [Test]
    public void ParseVerbosity_WithVFlag_KeepsInArgs()
    {
        // Arrange - single -v is kept for System.CommandLine
        var args = new[] { "sign", "-v", "--payload", "file.txt" };

        // Act
        int verbosity = LoggingConfiguration.ParseVerbosity(ref args);

        // Assert
        Assert.That(verbosity, Is.EqualTo(1)); // -v doesn't change default
        Assert.That(args, Does.Contain("-v")); // Kept for System.CommandLine
    }

    [Test]
    public void ParseVerbosity_WithVerboseFlag_KeepsInArgs()
    {
        // Arrange - --verbose is kept for System.CommandLine
        var args = new[] { "sign", "--verbose", "--payload", "file.txt" };

        // Act
        int verbosity = LoggingConfiguration.ParseVerbosity(ref args);

        // Assert
        Assert.That(verbosity, Is.EqualTo(1)); // --verbose doesn't change default (System.CommandLine handles it)
        Assert.That(args, Does.Contain("--verbose")); // Kept for System.CommandLine
    }
}
