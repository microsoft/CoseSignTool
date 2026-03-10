// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Abstractions.Tests.Security;

using CoseSignTool.Abstractions.IO;
using CoseSignTool.Abstractions.Security;

/// <summary>
/// Tests for the SystemConsole class.
/// Note: Full testing of console methods is limited since they delegate to System.Console.
/// These tests primarily verify the singleton pattern and interface implementation.
/// </summary>
[TestFixture]
public class SystemConsoleTests
{
    [Test]
    public void Instance_ReturnsSingletonInstance()
    {
        // Act
        var instance1 = SystemConsole.Instance;
        var instance2 = SystemConsole.Instance;

        // Assert
        Assert.That(instance1, Is.Not.Null);
        Assert.That(instance2, Is.SameAs(instance1));
    }

    [Test]
    public void Instance_ImplementsIConsole()
    {
        // Act
        var instance = SystemConsole.Instance;

        // Assert
        Assert.That(instance, Is.AssignableTo<IConsole>());
    }

    [Test]
    public void IsInputRedirected_ReturnsConsoleValue()
    {
        // Act
        var result = SystemConsole.Instance.IsInputRedirected;

        // Assert - Just verify it returns a boolean (matches Console.IsInputRedirected)
        Assert.That(result, Is.TypeOf<bool>());
    }

    [Test]
    public void IsUserInteractive_ReturnsEnvironmentValue()
    {
        // Act
        var result = SystemConsole.Instance.IsUserInteractive;

        // Assert - Should match Environment.UserInteractive
        Assert.That(result, Is.EqualTo(Environment.UserInteractive));
    }

    [Test]
    public void Write_DoesNotThrow()
    {
        // Arrange
        var console = SystemConsole.Instance;

        // Act & Assert - Should not throw
        Assert.DoesNotThrow(() => console.Write(null));
        Assert.DoesNotThrow(() => console.Write("test"));
        Assert.DoesNotThrow(() => console.Write(string.Empty));
    }

    [Test]
    public void WriteLine_DoesNotThrow()
    {
        // Arrange
        var console = SystemConsole.Instance;

        // Act & Assert - Should not throw
        Assert.DoesNotThrow(() => console.WriteLine());
        Assert.DoesNotThrow(() => console.WriteLine(null));
        Assert.DoesNotThrow(() => console.WriteLine("test"));
        Assert.DoesNotThrow(() => console.WriteLine(string.Empty));
    }
}
