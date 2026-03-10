// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;


[TestFixture]
[Category("Validation")]
public class TrustFactSetTests
{
    [Test]
    public void Available_WithNullValues_CreatesEmptyNonMissingSet()
    {
        var set = TrustFactSet<string>.Available(values: null);

        Assert.Multiple(() =>
        {
            Assert.That(set.IsMissing, Is.False);
            Assert.That(set.MissingReason, Is.Null);
            Assert.That(set.Values, Is.Empty);
        });
    }

    [Test]
    public void Missing_HasReasonAndNoValues()
    {
        var set = TrustFactSet<string>.Missing("CODE", "message");

        Assert.Multiple(() =>
        {
            Assert.That(set.IsMissing, Is.True);
            Assert.That(set.Values, Is.Empty);
            Assert.That(set.MissingReason, Is.Not.Null);
            Assert.That(set.MissingReason!.Code, Is.EqualTo("CODE"));
            Assert.That(set.MissingReason!.Message, Is.EqualTo("message"));
        });
    }
}
