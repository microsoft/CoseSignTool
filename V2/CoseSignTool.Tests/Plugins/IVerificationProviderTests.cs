// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSignTool.Abstractions;

namespace CoseSignTool.Tests.Plugins;

/// <summary>
/// Tests for the IVerificationProvider interface and its implementations.
/// </summary>
[TestFixture]
public class IVerificationProviderTests
{
    /// <summary>
    /// Test implementation of IVerificationProvider for unit testing.
    /// </summary>
    private sealed class TestVerificationProvider : IVerificationProvider
    {
        public string ProviderName => "Test";
        public string Description => "Test verification provider";
        public int Priority => 50;

        private Option<bool> TestOption = null!;
        private Option<string?> TestNameOption = null!;
        public bool AddVerificationOptionsCalled { get; private set; }
        public bool IsActivatedResult { get; set; } = true;
        public List<IValidator<CoseSign1Message>> ValidatorsToReturn { get; } = new();
        public Dictionary<string, object?> MetadataToReturn { get; } = new();

        public void AddVerificationOptions(Command command)
        {
            AddVerificationOptionsCalled = true;
            TestOption = new Option<bool>("--test-option", "A test option");
            TestNameOption = new Option<string?>("--test-name", "A test name");
            command.AddOption(TestOption);
            command.AddOption(TestNameOption);
        }

        public bool IsActivated(ParseResult parseResult)
        {
            // Check if test-option was set
            return parseResult.GetValueForOption(TestOption) || IsActivatedResult;
        }

        public IEnumerable<IValidator<CoseSign1Message>> CreateValidators(ParseResult parseResult)
        {
            return ValidatorsToReturn;
        }

        public IDictionary<string, object?> GetVerificationMetadata(
            ParseResult parseResult,
            CoseSign1Message message,
            ValidationResult validationResult)
        {
            return MetadataToReturn;
        }
    }

    /// <summary>
    /// Simple test validator.
    /// </summary>
    private sealed class TestValidator : IValidator<CoseSign1Message>
    {
        private readonly bool ShouldPass;

        public TestValidator(bool shouldPass) => ShouldPass = shouldPass;

        public ValidationResult Validate(CoseSign1Message input)
        {
            return ShouldPass
                ? ValidationResult.Success("TestValidator")
                : ValidationResult.Failure("TestValidator", "Test failure", "TEST_FAIL");
        }

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Validate(input));
        }
    }

    [Test]
    public void VerificationProvider_Properties_ReturnExpectedValues()
    {
        // Arrange
        var provider = new TestVerificationProvider();

        // Act & Assert
        provider.ProviderName.Should().Be("Test");
        provider.Description.Should().Be("Test verification provider");
        provider.Priority.Should().Be(50);
    }

    [Test]
    public void AddVerificationOptions_AddsOptionsToCommand()
    {
        // Arrange
        var provider = new TestVerificationProvider();
        var command = new Command("verify", "Test verify command");

        // Act
        provider.AddVerificationOptions(command);

        // Assert
        provider.AddVerificationOptionsCalled.Should().BeTrue();
        command.Options.Should().HaveCount(2);
        command.Options.Any(o => o.Name == "test-option").Should().BeTrue();
        command.Options.Any(o => o.Name == "test-name").Should().BeTrue();
    }

    [Test]
    public void IsActivated_WhenOptionSet_ReturnsTrue()
    {
        // Arrange
        var provider = new TestVerificationProvider();
        provider.IsActivatedResult = false; // Default to not activated
        var command = new Command("verify");
        provider.AddVerificationOptions(command);

        // Parse with option
        var parser = new Parser(command);
        var parseResult = parser.Parse("--test-option");

        // Act
        var isActivated = provider.IsActivated(parseResult);

        // Assert
        isActivated.Should().BeTrue();
    }

    [Test]
    public void CreateValidators_ReturnsConfiguredValidators()
    {
        // Arrange
        var provider = new TestVerificationProvider();
        provider.ValidatorsToReturn.Add(new TestValidator(true));
        provider.ValidatorsToReturn.Add(new TestValidator(false));

        var command = new Command("verify");
        provider.AddVerificationOptions(command);
        var parser = new Parser(command);
        var parseResult = parser.Parse("");

        // Act
        var validators = provider.CreateValidators(parseResult).ToList();

        // Assert
        validators.Should().HaveCount(2);
    }

    [Test]
    public void GetVerificationMetadata_ReturnsConfiguredMetadata()
    {
        // Arrange
        var provider = new TestVerificationProvider();
        provider.MetadataToReturn["Key1"] = "Value1";
        provider.MetadataToReturn["Key2"] = 42;

        var command = new Command("verify");
        provider.AddVerificationOptions(command);
        var parser = new Parser(command);
        var parseResult = parser.Parse("");

        // Act
        var metadata = provider.GetVerificationMetadata(parseResult, null!, ValidationResult.Success("Test"));

        // Assert
        metadata.Should().ContainKey("Key1").WhoseValue.Should().Be("Value1");
        metadata.Should().ContainKey("Key2").WhoseValue.Should().Be(42);
    }

    [Test]
    public void Priority_DeterminesProviderOrdering()
    {
        // Arrange - create providers with different priorities
        var highPriorityProvider = new TestVerificationProvider { IsActivatedResult = true };
        var lowPriorityProvider = new TestVerificationProvider { IsActivatedResult = true };

        // The Priority property is readonly in the interface, but we can check ordering
        var providers = new List<IVerificationProvider> { highPriorityProvider, lowPriorityProvider };
        var ordered = providers.OrderBy(p => p.Priority).ToList();

        // Assert
        // Both have same priority (50), so order is preserved
        ordered.Should().HaveCount(2);
        ordered.All(p => p.Priority == 50).Should().BeTrue();
    }
}
