// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace DIDx509.Tests;

using NUnit.Framework;

[TestFixture]
public class EkuPreferenceTests : DIDx509TestBase
{
    [Test]
    public void EkuPreference_First_SelectsFirstEku()
    {
        // Arrange - First EKU should be selected
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.10.3.13"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.First);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.3.6.1.5.5.7.3.1");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.1"));
    }

    [Test]
    public void EkuPreference_MostSpecific_SelectsEkuWithMostSegments()
    {
        // Arrange - MostSpecific should select the one with most segments (10 segments)
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.2.3.4", "1.3.6.1.5.5.7.3", "1.3.6.1.4.1.311.10.3.13"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.MostSpecific);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.3.6.1.4.1.311.10.3.13");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.10.3.13"));
    }

    [Test]
    public void EkuPreference_Largest_SelectsNumericallyLargestOid()
    {
        // Arrange - Largest should select numerically largest (2.5.29.100 > 1.x)
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.2.3.4", "1.3.6.1.5.5.7.3.2", "2.5.29.100"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.Largest);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "2.5.29.100");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:2.5.29.100"));
    }

    [Test]
    public void EkuPreference_Largest_ComparesSegmentBySegment()
    {
        // Arrange - 2.5.29.17: first segment 2 > 1, should win
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.3.6.1.5.5.7.3.1", "2.5.29.17", "1.2.3.4.5"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.Largest);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "2.5.29.17");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:2.5.29.17"));
    }

    [Test]
    public void EkuPreference_Largest_WithDifferentLengths_ComparesNumerically()
    {
        // Arrange - Longer OID wins when prefix matches: 1.2.3.4.5 > 1.2.3
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.2.3", "1.2.3.4.5", "1.2.3.4"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.Largest);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.2.3.4.5");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:1.2.3.4.5"));
    }

    [Test]
    public void EkuPreference_Largest_WithLargeNumbers_ComparesCorrectly()
    {
        // Arrange - 999 > 840 in second segment
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.2.840", "1.2.999", "1.2.100"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.Largest);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.2.999");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:1.2.999"));
    }

    [Test]
    public void EkuPreference_MostSpecificAndLargest_PrioritizesSpecificity()
    {
        // Arrange - 5 segments wins over 4, regardless of values
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["2.5.29.100", "1.2.3.4", "1.2.3.4.100"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.MostSpecificAndLargest);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.2.3.4.100");
        AssertDidContainsCertHash(did, root, "sha256");
        // Should select 5-segment OID regardless of last segment value
        Assert.That(did, Does.Contain("::eku:1.2.3.4.100"));
    }

    [Test]
    public void EkuPreference_MostSpecificAndLargest_TieBreaksWithLastSegment()
    {
        // Arrange - Same length, largest last segment wins (100 > 50)
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.2.3.4.50", "1.2.3.4.100", "1.2.3.4.25"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.MostSpecificAndLargest);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.2.3.4.100");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:1.2.3.4.100"));
    }

    [Test]
    public void EkuPreference_MostSpecificAndLargest_WithThreeOidsSameLength_SelectsLargestLast()
    {
        // Arrange - Three OIDs same length, select largest
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.2.3.4.25", "1.2.3.4.50", "1.2.3.4.100"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.MostSpecificAndLargest);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.2.3.4.100");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:1.2.3.4.100"));
    }

    [Test]
    public void EkuPreference_WithPrefixFilter_FiltersBeforeSelection()
    {
        // Arrange - Mix of standard and Microsoft-specific EKUs
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.4.1.311.10.3.12", "1.3.6.1.4.1.311.10.3.13"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act - Filter to Microsoft OIDs only, select most specific
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.MostSpecific, "1.3.6.1.4.1");

        // Assert
        AssertDidStructure(did, "sha256", root, "eku");
        AssertDidContainsCertHash(did, root, "sha256");
        // Both Microsoft OIDs have same length, should get first one after filtering
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.10.3."));
        Assert.That(did, Does.Not.Contain("::eku:1.3.6.1.5.5.7.3.1"));
    }

    [Test]
    public void EkuPreference_WithPrefixFilter_NoMatch_OmitsEkuPolicy()
    {
        // Arrange - Only standard OIDs, no Microsoft OIDs
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.3.6.1.5.5.7.3.2"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act - Filter to Microsoft OIDs (no match)
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.First, "1.3.6.1.4.1");

        // Assert
        Assert.That(did, Does.Contain("::subject:"));
        Assert.That(did, Does.Not.Contain("::eku:"));
    }

    [Test]
    public void EkuPreference_Largest_WithIdenticalPrefix_ComparesLaterSegments()
    {
        // Arrange - Same prefix, compare last segment: 100 > 2 > 1
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.100"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.Largest);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.3.6.1.5.5.7.3.100");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:1.3.6.1.5.5.7.3.100"));
    }

    [Test]
    public void EkuPreference_Largest_StringLength_DoesNotAffectComparison()
    {
        // Arrange - "2.16.840.1.113730" is longer string but 2 > 1 numerically
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.2.3", "2.16.840.1.113730", "1.3.6.1.5.5.7.3.1"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.Largest);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "2.16.840.1.113730");
        AssertDidContainsCertHash(did, root, "sha256");
        // Should select numerically larger, not longer string
        Assert.That(did, Does.Contain("::eku:2.16.840.1.113730"));
    }

    [Test]
    public void EkuPreference_MostSpecific_IgnoresNumericValues()
    {
        // Arrange - 10 segments is most specific
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["2.16.840.1.113730", "1.2.3.4.5.6", "1.3.6.1.4.1.311.10.3.13"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did = leaf.GetDidWithRootAndEku(chain, EkuPreference.MostSpecific);

        // Assert
        AssertDidStructure(did, "sha256", root, "eku", "1.3.6.1.4.1.311.10.3.13");
        AssertDidContainsCertHash(did, root, "sha256");
        Assert.That(did, Does.Contain("::eku:1.3.6.1.4.1.311.10.3.13"));
    }

    [Test]
    public void EkuPreference_WithSingleEku_AllPreferencesReturnSameResult()
    {
        // Arrange - Single EKU, all preferences should return same result
        using var leaf = CreateTestCertificate("CN=Leaf", customEkus: ["1.3.6.1.5.5.7.3.2"]);
        using var root = CreateSelfSignedCertificate("CN=Root");
        var chain = new[] { leaf, root };

        // Act
        string did1 = leaf.GetDidWithRootAndEku(chain, EkuPreference.First);
        string did2 = leaf.GetDidWithRootAndEku(chain, EkuPreference.MostSpecific);
        string did3 = leaf.GetDidWithRootAndEku(chain, EkuPreference.Largest);
        string did4 = leaf.GetDidWithRootAndEku(chain, EkuPreference.MostSpecificAndLargest);

        // Assert
        Assert.That(did1, Is.EqualTo(did2));
        Assert.That(did2, Is.EqualTo(did3));
        Assert.That(did3, Is.EqualTo(did4));
    }

}