// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
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
        public List<IValidator> ValidatorsToReturn { get; } = new();
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

        public IEnumerable<IValidator> CreateValidators(ParseResult parseResult)
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
    private sealed class TestValidator : IValidator
    {
        private readonly bool ShouldPass;

        private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.Signature };

        public TestValidator(bool shouldPass) => ShouldPass = shouldPass;

        public IReadOnlyCollection<ValidationStage> Stages => StagesField;

        public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
        {
            return ShouldPass
                ? ValidationResult.Success("TestValidator")
                : ValidationResult.Failure("TestValidator", "Test failure", "TEST_FAIL");
        }

        public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Validate(input, stage));
        }
    }

    [Test]
    public void VerificationProvider_Properties_ReturnExpectedValues()
    {
        // Arrange
        var provider = new TestVerificationProvider();

        // Act & Assert
        Assert.That(provider.ProviderName, Is.EqualTo("Test"));
        Assert.That(provider.Description, Is.EqualTo("Test verification provider"));
        Assert.That(provider.Priority, Is.EqualTo(50));
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
        Assert.That(provider.AddVerificationOptionsCalled, Is.True);
        Assert.That(command.Options, Has.Count.EqualTo(2));
        Assert.That(command.Options.Any(o => o.Name == "test-option"), Is.True);
        Assert.That(command.Options.Any(o => o.Name == "test-name"), Is.True);
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
        Assert.That(isActivated, Is.True);
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
        Assert.That(validators, Has.Count.EqualTo(2));
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
        Assert.That(metadata, Does.ContainKey("Key1"));
        Assert.That(metadata["Key1"], Is.EqualTo("Value1"));
        Assert.That(metadata, Does.ContainKey("Key2"));
        Assert.That(metadata["Key2"], Is.EqualTo(42));
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
        Assert.That(ordered, Has.Count.EqualTo(2));
        Assert.That(ordered.All(p => p.Priority == 50), Is.True);
    }
}