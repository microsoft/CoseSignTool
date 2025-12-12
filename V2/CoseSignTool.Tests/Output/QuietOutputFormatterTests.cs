// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Output;

namespace CoseSignTool.Tests.Output;

/// <summary>
/// Tests for the QuietOutputFormatter class.
/// </summary>
public class QuietOutputFormatterTests
{
    [Fact]
    public void WriteSuccess_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.WriteSuccess("Test");
    }

    [Fact]
    public void WriteError_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.WriteError("Test");
    }

    [Fact]
    public void WriteInfo_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.WriteInfo("Test");
    }

    [Fact]
    public void WriteWarning_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.WriteWarning("Test");
    }

    [Fact]
    public void WriteKeyValue_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.WriteKeyValue("Key", "Value");
    }

    [Fact]
    public void BeginSection_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.BeginSection("Test");
    }

    [Fact]
    public void EndSection_ProducesNoOutput()
    {
        // Arrange
        var formatter = new QuietOutputFormatter();

        // Act & Assert - should not throw
        formatter.EndSection();
    }
}
