// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Configuration;
using Microsoft.Extensions.Configuration;

namespace CoseSignTool.Tests.Configuration;

/// <summary>
/// Tests for the ConfigurationLoader class.
/// </summary>
public class ConfigurationLoaderTests
{
    [Fact]
    public void LoadConfiguration_WithNoSources_ReturnsEmptyConfiguration()
    {
        // Arrange
        var loader = new ConfigurationLoader();

        // Act
        var config = loader.Build();

        // Assert
        config.Should().NotBeNull();
        config.AsEnumerable().Should().BeEmpty();
    }

    [Fact]
    public void LoadConfiguration_WithEnvironmentVariables_LoadsCorrectly()
    {
        // Arrange
        Environment.SetEnvironmentVariable("COSESIGNTOOL_TestKey", "TestValue");
        var loader = new ConfigurationLoader()
            .AddEnvironmentVariables("COSESIGNTOOL_");

        try
        {
            // Act
            var config = loader.Build();

            // Assert
            config["TestKey"].Should().Be("TestValue");
        }
        finally
        {
            Environment.SetEnvironmentVariable("COSESIGNTOOL_TestKey", null);
        }
    }

    [Theory]
    [InlineData("key1", "value1")]
    [InlineData("Section:Key2", "value2")]
    [InlineData("Section:SubSection:Key3", "value3")]
    public void LoadConfiguration_WithInMemoryValues_LoadsCorrectly(string key, string value)
    {
        // Arrange
        var loader = new ConfigurationLoader()
            .AddInMemoryCollection(new Dictionary<string, string?> { [key] = value });

        // Act
        var config = loader.Build();

        // Assert
        config[key].Should().Be(value);
    }

    [Fact]
    public void LoadConfiguration_WithMultipleSources_LaterSourcesOverrideEarlier()
    {
        // Arrange
        var loader = new ConfigurationLoader()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = "FirstValue" })
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = "SecondValue" });

        // Act
        var config = loader.Build();

        // Assert
        config["Key"].Should().Be("SecondValue");
    }

    [Fact]
    public void LoadConfiguration_CanBuildMultipleTimes()
    {
        // Arrange
        var loader = new ConfigurationLoader()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = "Value" });

        // Act
        var config1 = loader.Build();
        var config2 = loader.Build();

        // Assert
        config1.Should().NotBeSameAs(config2);
        config1["Key"].Should().Be("Value");
        config2["Key"].Should().Be("Value");
    }

    [Fact]
    public void LoadConfiguration_WithNullKey_ThrowsArgumentNullException()
    {
        // Arrange
        var loader = new ConfigurationLoader()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = "Value" });
        var config = loader.Build();

        // Act
        Action act = () => _ = config[null!];

        // Assert
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void GetSection_WithValidSectionName_ReturnsSection()
    {
        // Arrange
        var loader = new ConfigurationLoader()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Section:Key1"] = "Value1",
                ["Section:Key2"] = "Value2",
                ["OtherSection:Key3"] = "Value3"
            });
        var config = loader.Build();

        // Act
        var section = config.GetSection("Section");

        // Assert
        section.Should().NotBeNull();
        section["Key1"].Should().Be("Value1");
        section["Key2"].Should().Be("Value2");
        section.GetChildren().Should().HaveCount(2);
    }

    [Fact]
    public void GetSection_WithNonExistentSection_ReturnsEmptySection()
    {
        // Arrange
        var loader = new ConfigurationLoader()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = "Value" });
        var config = loader.Build();

        // Act
        var section = config.GetSection("NonExistent");

        // Assert
        section.Should().NotBeNull();
        section.Value.Should().BeNull();
        section.Exists().Should().BeFalse();
    }

    [Fact]
    public void Bind_WithValidObject_PopulatesProperties()
    {
        // Arrange
        var loader = new ConfigurationLoader()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["TestConfig:StringValue"] = "Test",
                ["TestConfig:IntValue"] = "42",
                ["TestConfig:BoolValue"] = "true"
            });
        var config = loader.Build();
        var testConfig = new TestConfig();

        // Act
        config.GetSection("TestConfig").Bind(testConfig);

        // Assert
        testConfig.StringValue.Should().Be("Test");
        testConfig.IntValue.Should().Be(42);
        testConfig.BoolValue.Should().BeTrue();
    }

    [Fact]
    public void AddEnvironmentVariables_WithCustomPrefix_FiltersCorrectly()
    {
        // Arrange
        Environment.SetEnvironmentVariable("CUSTOM_Key1", "Value1");
        Environment.SetEnvironmentVariable("OTHER_Key2", "Value2");
        var loader = new ConfigurationLoader()
            .AddEnvironmentVariables("CUSTOM_");

        try
        {
            // Act
            var config = loader.Build();

            // Assert
            config["Key1"].Should().Be("Value1");
            config["Key2"].Should().BeNull();
        }
        finally
        {
            Environment.SetEnvironmentVariable("CUSTOM_Key1", null);
            Environment.SetEnvironmentVariable("OTHER_Key2", null);
        }
    }

    [Fact]
    public void AddEnvironmentVariables_WithNullPrefix_LoadsAllEnvironmentVariables()
    {
        // Arrange
        Environment.SetEnvironmentVariable("COSESIGN_TestKey", "TestValue");
        var loader = new ConfigurationLoader()
            .AddEnvironmentVariables(null);

        try
        {
            // Act
            var config = loader.Build();

            // Assert
            config["COSESIGN_TestKey"].Should().Be("TestValue");
        }
        finally
        {
            Environment.SetEnvironmentVariable("COSESIGN_TestKey", null);
        }
    }

    [Fact]
    public void AddEnvironmentVariables_WithEmptyPrefix_LoadsAllEnvironmentVariables()
    {
        // Arrange
        Environment.SetEnvironmentVariable("COSESIGN_AnotherKey", "AnotherValue");
        var loader = new ConfigurationLoader()
            .AddEnvironmentVariables(string.Empty);

        try
        {
            // Act
            var config = loader.Build();

            // Assert
            config["COSESIGN_AnotherKey"].Should().Be("AnotherValue");
        }
        finally
        {
            Environment.SetEnvironmentVariable("COSESIGN_AnotherKey", null);
        }
    }

    private class TestConfig
    {
        public string StringValue { get; set; } = string.Empty;
        public int IntValue { get; set; }
        public bool BoolValue { get; set; }
    }
}
