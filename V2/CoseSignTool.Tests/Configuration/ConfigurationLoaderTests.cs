// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSignTool.Configuration;
using Microsoft.Extensions.Configuration;

namespace CoseSignTool.Tests.Configuration;

/// <summary>
/// Tests for the ConfigurationLoader class.
/// </summary>
[TestFixture]
public class ConfigurationLoaderTests
{
    [Test]
    public void LoadConfiguration_WithNoSources_ReturnsEmptyConfiguration()
    {
        // Arrange
        var loader = new ConfigurationLoader();

        // Act
        var config = loader.Build();

        // Assert
        Assert.That(config, Is.Not.Null);
        var entries = config.AsEnumerable().Where(kv => kv.Value != null).ToList();
        Assert.That(entries.Count == 0, Is.True, "Configuration should be empty");
    }

    [Test]
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
            Assert.That(config["TestKey"], Is.EqualTo("TestValue"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("COSESIGNTOOL_TestKey", null);
        }
    }

    [TestCase("key1", "value1")]
    [TestCase("Section:Key2", "value2")]
    [TestCase("Section:SubSection:Key3", "value3")]
    public void LoadConfiguration_WithInMemoryValues_LoadsCorrectly(string key, string value)
    {
        // Arrange
        var loader = new ConfigurationLoader()
            .AddInMemoryCollection(new Dictionary<string, string?> { [key] = value });

        // Act
        var config = loader.Build();

        // Assert
        Assert.That(config[key], Is.EqualTo(value));
    }

    [Test]
    public void LoadConfiguration_WithMultipleSources_LaterSourcesOverrideEarlier()
    {
        // Arrange
        var loader = new ConfigurationLoader()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = "FirstValue" })
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = "SecondValue" });

        // Act
        var config = loader.Build();

        // Assert
        Assert.That(config["Key"], Is.EqualTo("SecondValue"));
    }

    [Test]
    public void LoadConfiguration_CanBuildMultipleTimes()
    {
        // Arrange
        var loader = new ConfigurationLoader()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = "Value" });

        // Act
        var config1 = loader.Build();
        var config2 = loader.Build();

        // Assert
        Assert.That(config2, Is.Not.SameAs(config1));
        Assert.That(config1["Key"], Is.EqualTo("Value"));
        Assert.That(config2["Key"], Is.EqualTo("Value"));
    }

    [Test]
    public void LoadConfiguration_WithNullKey_ThrowsArgumentNullException()
    {
        // Arrange
        var loader = new ConfigurationLoader()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = "Value" });
        var config = loader.Build();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => _ = config[null!]);
    }

    [Test]
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
        Assert.That(section, Is.Not.Null);
        Assert.That(section["Key1"], Is.EqualTo("Value1"));
        Assert.That(section["Key2"], Is.EqualTo("Value2"));
        Assert.That(section.GetChildren().Count(), Is.EqualTo(2));
    }

    [Test]
    public void GetSection_WithNonExistentSection_ReturnsEmptySection()
    {
        // Arrange
        var loader = new ConfigurationLoader()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Key"] = "Value" });
        var config = loader.Build();

        // Act
        var section = config.GetSection("NonExistent");

        // Assert
        Assert.That(section, Is.Not.Null);
        Assert.That(section.Value, Is.Null);
        Assert.That(section.Exists(), Is.False);
    }

    [Test]
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
        Assert.That(testConfig.StringValue, Is.EqualTo("Test"));
        Assert.That(testConfig.IntValue, Is.EqualTo(42));
        Assert.That(testConfig.BoolValue, Is.True);
    }

    [Test]
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
            Assert.That(config["Key1"], Is.EqualTo("Value1"));
            Assert.That(config["Key2"], Is.Null);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CUSTOM_Key1", null);
            Environment.SetEnvironmentVariable("OTHER_Key2", null);
        }
    }

    [Test]
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
            Assert.That(config["COSESIGN_TestKey"], Is.EqualTo("TestValue"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("COSESIGN_TestKey", null);
        }
    }

    [Test]
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
            Assert.That(config["COSESIGN_AnotherKey"], Is.EqualTo("AnotherValue"));
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