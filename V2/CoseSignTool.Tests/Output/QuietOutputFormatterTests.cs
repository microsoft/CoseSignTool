// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Output;

namespace CoseSignTool.Tests.Output;

/// <summary>
/// Tests for the QuietOutputFormatter class.
/// </summary>
[TestFixture]
public class QuietOutputFormatterTests
{
    [Test]
    public void WriteSuccess_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.WriteSuccess("Test");
    }

    [Test]
    public void WriteError_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.WriteError("Test");
    }

    [Test]
    public void WriteInfo_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.WriteInfo("Test");
    }

    [Test]
    public void WriteWarning_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.WriteWarning("Test");
    }

    [Test]
    public void WriteKeyValue_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.WriteKeyValue("Key", "Value");
    }

    [Test]
    public void BeginSection_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.BeginSection("Test");
    }

    [Test]
    public void EndSection_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.EndSection();
    }

    [Test]
    public void WriteStructuredData_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();
        var structuredData = new { name = "Test", value = 42 };

        // Act & Assert - should not throw
        formatter.WriteStructuredData(structuredData);
        formatter.Flush();
    }
}