// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using CoseSign1.Tests.Common;
using CoseSign1.Validation.Abstractions;

/// <summary>
/// Tests for <see cref="ValidationComponentBase"/> and <see cref="ValidationComponentOptions"/>.
/// </summary>
[TestFixture]
[Category("Validation")]
public class ValidationComponentBaseTests
{
    #region Test Implementation Classes

    /// <summary>
    /// Test component that always says it's applicable.
    /// </summary>
    private class TestAlwaysApplicableComponent : ValidationComponentBase
    {
        public TestAlwaysApplicableComponent(ValidationComponentOptions? options = null)
            : base(options)
        {
        }

        public override string ComponentName => "TestAlwaysApplicable";
    }

    /// <summary>
    /// Test component that never says it's applicable.
    /// </summary>
    private class TestNeverApplicableComponent : ValidationComponentBase
    {
        public TestNeverApplicableComponent(ValidationComponentOptions? options = null)
            : base(options)
        {
        }

        public override string ComponentName => "TestNeverApplicable";

        protected override bool ComputeApplicability(CoseSign1Message message, CoseSign1ValidationOptions? options = null) => false;
    }

    /// <summary>
    /// Test component that tracks how many times ComputeApplicability is called.
    /// </summary>
    private class TestCountingComponent : ValidationComponentBase
    {
        public int ComputeApplicabilityCallCount { get; private set; }

        public TestCountingComponent(ValidationComponentOptions? options = null)
            : base(options)
        {
        }

        public override string ComponentName => "TestCountingComponent";

        protected override bool ComputeApplicability(CoseSign1Message message, CoseSign1ValidationOptions? options = null)
        {
            ComputeApplicabilityCallCount++;
            return true;
        }

        public void ClearCache() => ClearApplicabilityCache();
    }

    /// <summary>
    /// Test component that changes applicability based on options.
    /// </summary>
    private class TestOptionsBasedComponent : ValidationComponentBase
    {
        public TestOptionsBasedComponent(ValidationComponentOptions? options = null)
            : base(options)
        {
        }

        public override string ComponentName => "TestOptionsBasedComponent";

        protected override bool ComputeApplicability(CoseSign1Message message, CoseSign1ValidationOptions? options = null) =>
            options?.CertificateHeaderLocation == CoseHeaderLocation.Any;
    }

    #endregion

    #region IsApplicableTo Tests

    [Test]
    public void IsApplicableTo_NullMessage_ReturnsFalse()
    {
        var component = new TestAlwaysApplicableComponent();

        var result = component.IsApplicableTo(null);

        Assert.That(result, Is.False);
    }

    [Test]
    public void IsApplicableTo_ValidMessage_ReturnsTrue()
    {
        var component = new TestAlwaysApplicableComponent();
        var message = CreateSignedMessage();

        var result = component.IsApplicableTo(message);

        Assert.That(result, Is.True);
    }

    [Test]
    public void IsApplicableTo_NeverApplicableComponent_ReturnsFalse()
    {
        var component = new TestNeverApplicableComponent();
        var message = CreateSignedMessage();

        var result = component.IsApplicableTo(message);

        Assert.That(result, Is.False);
    }

    [Test]
    public void IsApplicableTo_WithOptions_PassesOptionsToComputeApplicability()
    {
        var component = new TestOptionsBasedComponent();
        var message = CreateSignedMessage();

        // Without the option set, should be false
        var result1 = component.IsApplicableTo(message, new CoseSign1ValidationOptions { CertificateHeaderLocation = CoseHeaderLocation.Protected });
        // With the option set to Any, should be true
        var result2 = component.IsApplicableTo(message, new CoseSign1ValidationOptions { CertificateHeaderLocation = CoseHeaderLocation.Any });

        Assert.Multiple(() =>
        {
            Assert.That(result1, Is.False);
            Assert.That(result2, Is.True);
        });
    }

    #endregion

    #region Caching Tests

    [Test]
    public void IsApplicableTo_NoCacheStrategy_DoesNotCache()
    {
        var options = new ValidationComponentOptions { CachingStrategy = CachingStrategy.None };
        var component = new TestCountingComponent(options);
        var message = CreateSignedMessage();

        // Call multiple times
        component.IsApplicableTo(message);
        component.IsApplicableTo(message);
        component.IsApplicableTo(message);

        // Should compute each time because caching is disabled
        Assert.That(component.ComputeApplicabilityCallCount, Is.EqualTo(3));
    }

    [Test]
    public void IsApplicableTo_SlidingExpirationStrategy_CachesResult()
    {
        var options = new ValidationComponentOptions
        {
            CachingStrategy = CachingStrategy.SlidingExpiration,
            CacheExpiration = TimeSpan.FromMinutes(5)
        };
        var component = new TestCountingComponent(options);
        var message = CreateSignedMessage();

        // Call multiple times with same message
        component.IsApplicableTo(message);
        component.IsApplicableTo(message);
        component.IsApplicableTo(message);

        // Should only compute once because result is cached
        Assert.That(component.ComputeApplicabilityCallCount, Is.EqualTo(1));
    }

    [Test]
    public void IsApplicableTo_AbsoluteExpirationStrategy_CachesResult()
    {
        var options = new ValidationComponentOptions
        {
            CachingStrategy = CachingStrategy.AbsoluteExpiration,
            CacheExpiration = TimeSpan.FromMinutes(5)
        };
        var component = new TestCountingComponent(options);
        var message = CreateSignedMessage();

        // Call multiple times with same message
        component.IsApplicableTo(message);
        component.IsApplicableTo(message);
        component.IsApplicableTo(message);

        // Should only compute once because result is cached
        Assert.That(component.ComputeApplicabilityCallCount, Is.EqualTo(1));
    }

    [Test]
    public void IsApplicableTo_DifferentMessages_ComputesEach()
    {
        var options = new ValidationComponentOptions
        {
            CachingStrategy = CachingStrategy.SlidingExpiration,
            CacheExpiration = TimeSpan.FromMinutes(5)
        };
        var component = new TestCountingComponent(options);
        var message1 = CreateSignedMessage();
        var message2 = CreateSignedMessage();

        component.IsApplicableTo(message1);
        component.IsApplicableTo(message2);

        // Should compute for each different message
        Assert.That(component.ComputeApplicabilityCallCount, Is.EqualTo(2));
    }

    [Test]
    public void IsApplicableTo_DifferentOptions_ComputesEach()
    {
        var options = new ValidationComponentOptions
        {
            CachingStrategy = CachingStrategy.SlidingExpiration,
            CacheExpiration = TimeSpan.FromMinutes(5)
        };
        var component = new TestCountingComponent(options);
        var message = CreateSignedMessage();
        var validationOptions1 = new CoseSign1ValidationOptions { CertificateHeaderLocation = CoseHeaderLocation.Protected };
        var validationOptions2 = new CoseSign1ValidationOptions { CertificateHeaderLocation = CoseHeaderLocation.Any };

        component.IsApplicableTo(message, validationOptions1);
        component.IsApplicableTo(message, validationOptions2);

        // Should compute for each different options configuration
        Assert.That(component.ComputeApplicabilityCallCount, Is.EqualTo(2));
    }

    [Test]
    public void ClearApplicabilityCache_ClearsOnlyThisComponentsCache()
    {
        var options = new ValidationComponentOptions
        {
            CachingStrategy = CachingStrategy.SlidingExpiration,
            CacheExpiration = TimeSpan.FromMinutes(5)
        };
        var component = new TestCountingComponent(options);
        var message = CreateSignedMessage();

        // Populate the cache
        component.IsApplicableTo(message);
        Assert.That(component.ComputeApplicabilityCallCount, Is.EqualTo(1));

        // Clear cache
        component.ClearCache();

        // Should compute again after cache clear
        component.IsApplicableTo(message);
        Assert.That(component.ComputeApplicabilityCallCount, Is.EqualTo(2));
    }

    #endregion

    #region ValidationComponentOptions Tests

    [Test]
    public void ValidationComponentOptions_Default_HasExpectedValues()
    {
        var options = ValidationComponentOptions.Default;

        Assert.Multiple(() =>
        {
            Assert.That(options.CachingStrategy, Is.EqualTo(CachingStrategy.SlidingExpiration));
            Assert.That(options.CacheExpiration, Is.EqualTo(TimeSpan.FromMinutes(5)));
        });
    }

    [Test]
    public void ValidationComponentOptions_NoCache_HasNoneStrategy()
    {
        var options = ValidationComponentOptions.NoCache;

        Assert.That(options.CachingStrategy, Is.EqualTo(CachingStrategy.None));
    }

    [Test]
    public void ValidationComponentOptions_DefaultCacheExpiration_IsFiveMinutes()
    {
        Assert.That(ValidationComponentOptions.DefaultCacheExpiration, Is.EqualTo(TimeSpan.FromMinutes(5)));
    }

    [Test]
    public void ValidationComponentOptions_CanBeCreatedWithInit()
    {
        var options = new ValidationComponentOptions
        {
            CachingStrategy = CachingStrategy.AbsoluteExpiration,
            CacheExpiration = TimeSpan.FromMinutes(10)
        };

        Assert.Multiple(() =>
        {
            Assert.That(options.CachingStrategy, Is.EqualTo(CachingStrategy.AbsoluteExpiration));
            Assert.That(options.CacheExpiration, Is.EqualTo(TimeSpan.FromMinutes(10)));
        });
    }

    [Test]
    public void ValidationComponentOptions_RecordEquality()
    {
        var options1 = new ValidationComponentOptions
        {
            CachingStrategy = CachingStrategy.SlidingExpiration,
            CacheExpiration = TimeSpan.FromMinutes(5)
        };
        var options2 = new ValidationComponentOptions
        {
            CachingStrategy = CachingStrategy.SlidingExpiration,
            CacheExpiration = TimeSpan.FromMinutes(5)
        };
        var options3 = new ValidationComponentOptions
        {
            CachingStrategy = CachingStrategy.None,
            CacheExpiration = TimeSpan.FromMinutes(5)
        };

        Assert.Multiple(() =>
        {
            Assert.That(options1, Is.EqualTo(options2));
            Assert.That(options1, Is.Not.EqualTo(options3));
        });
    }

    [Test]
    public void ValidationComponentOptions_WithSlidingExpiration_CreatesExpectedOptions()
    {
        var duration = TimeSpan.FromMinutes(10);

        var options = ValidationComponentOptions.WithSlidingExpiration(duration);

        Assert.Multiple(() =>
        {
            Assert.That(options.CachingStrategy, Is.EqualTo(CachingStrategy.SlidingExpiration));
            Assert.That(options.CacheExpiration, Is.EqualTo(duration));
        });
    }

    [Test]
    public void ValidationComponentOptions_WithAbsoluteExpiration_CreatesExpectedOptions()
    {
        var duration = TimeSpan.FromMinutes(15);

        var options = ValidationComponentOptions.WithAbsoluteExpiration(duration);

        Assert.Multiple(() =>
        {
            Assert.That(options.CachingStrategy, Is.EqualTo(CachingStrategy.AbsoluteExpiration));
            Assert.That(options.CacheExpiration, Is.EqualTo(duration));
        });
    }

    [Test]
    public void ValidationComponentOptions_WithSlidingExpiration_ZeroDuration()
    {
        var options = ValidationComponentOptions.WithSlidingExpiration(TimeSpan.Zero);

        Assert.Multiple(() =>
        {
            Assert.That(options.CachingStrategy, Is.EqualTo(CachingStrategy.SlidingExpiration));
            Assert.That(options.CacheExpiration, Is.EqualTo(TimeSpan.Zero));
        });
    }

    [Test]
    public void ValidationComponentOptions_WithAbsoluteExpiration_LargeDuration()
    {
        var duration = TimeSpan.FromHours(24);
        var options = ValidationComponentOptions.WithAbsoluteExpiration(duration);

        Assert.Multiple(() =>
        {
            Assert.That(options.CachingStrategy, Is.EqualTo(CachingStrategy.AbsoluteExpiration));
            Assert.That(options.CacheExpiration, Is.EqualTo(duration));
        });
    }

    [Test]
    public void ValidationComponentOptions_Defaults_AreImmutable()
    {
        // Get references to the static instances
        var default1 = ValidationComponentOptions.Default;
        var default2 = ValidationComponentOptions.Default;
        var noCache1 = ValidationComponentOptions.NoCache;
        var noCache2 = ValidationComponentOptions.NoCache;

        Assert.Multiple(() =>
        {
            Assert.That(default1, Is.SameAs(default2));
            Assert.That(noCache1, Is.SameAs(noCache2));
        });
    }

    [Test]
    public void ValidationComponentOptions_DefaultValues_WhenCreatedWithNew()
    {
        var options = new ValidationComponentOptions();

        Assert.Multiple(() =>
        {
            Assert.That(options.CachingStrategy, Is.EqualTo(CachingStrategy.SlidingExpiration));
            Assert.That(options.CacheExpiration, Is.EqualTo(ValidationComponentOptions.DefaultCacheExpiration));
        });
    }

    #endregion

    #region Constructor Tests

    [Test]
    public void Constructor_DefaultOptions_UsesDefaultComponentOptions()
    {
        var component = new TestAlwaysApplicableComponent();

        // Access through IsApplicableTo which uses ComponentOptions
        var message = CreateSignedMessage();
        var result = component.IsApplicableTo(message);

        Assert.That(result, Is.True);
    }

    [Test]
    public void Constructor_NullOptions_UsesDefaultComponentOptions()
    {
        var component = new TestAlwaysApplicableComponent(null);

        var message = CreateSignedMessage();
        var result = component.IsApplicableTo(message);

        Assert.That(result, Is.True);
    }

    [Test]
    public void Constructor_CustomOptions_UsesProvidedOptions()
    {
        var options = new ValidationComponentOptions
        {
            CachingStrategy = CachingStrategy.None
        };
        var component = new TestCountingComponent(options);
        var message = CreateSignedMessage();

        // Call twice - both should compute since caching is disabled
        component.IsApplicableTo(message);
        component.IsApplicableTo(message);

        Assert.That(component.ComputeApplicabilityCallCount, Is.EqualTo(2));
    }

    #endregion

    #region ComponentName Tests

    [Test]
    public void ComponentName_ReturnsExpectedValue()
    {
        var component1 = new TestAlwaysApplicableComponent();
        var component2 = new TestNeverApplicableComponent();
        var component3 = new TestCountingComponent();

        Assert.Multiple(() =>
        {
            Assert.That(component1.ComponentName, Is.EqualTo("TestAlwaysApplicable"));
            Assert.That(component2.ComponentName, Is.EqualTo("TestNeverApplicable"));
            Assert.That(component3.ComponentName, Is.EqualTo("TestCountingComponent"));
        });
    }

    #endregion

    #region CachingStrategy Enum Tests

    [Test]
    public void CachingStrategy_EnumValues_AreExpected()
    {
        var values = Enum.GetValues<CachingStrategy>();

        Assert.Multiple(() =>
        {
            Assert.That(values, Contains.Item(CachingStrategy.None));
            Assert.That(values, Contains.Item(CachingStrategy.SlidingExpiration));
            Assert.That(values, Contains.Item(CachingStrategy.AbsoluteExpiration));
            Assert.That(values, Has.Length.EqualTo(3));
        });
    }

    #endregion

    #region Helper Methods

    private static CoseSign1Message CreateSignedMessage()
    {
        using var cert = TestCertificateUtils.CreateCertificate("Test", useEcc: true);
        var payload = "Test payload"u8.ToArray();

        using var key = cert.GetECDsaPrivateKey()!;
        var signer = new CoseSigner(key, HashAlgorithmName.SHA256);
        var signedBytes = CoseSign1Message.SignEmbedded(payload, signer);
        return CoseMessage.DecodeSign1(signedBytes);
    }

    #endregion
}
