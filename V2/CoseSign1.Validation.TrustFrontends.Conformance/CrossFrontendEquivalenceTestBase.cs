// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance;

using System.Collections.Generic;
using System.Globalization;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Json;
using NUnit.Framework;

/// <summary>
/// Reusable cross-frontend equivalence harness (§6.5.10 #8). Frontend test projects derive
/// concrete fixtures from this base to assert that two frontends translate the same logical
/// fixture name into byte-identical canonical IRs.
/// </summary>
/// <typeparam name="TDocumentA">Document type for frontend A.</typeparam>
/// <typeparam name="TDocumentB">Document type for frontend B.</typeparam>
/// <remarks>
/// <para>
/// Phase 4 ships only the JSON frontend, so the only concrete derivation is a degenerate
/// (json, json) pair (see <see cref="FrontendConformanceTestBase{TDocument}.Conformance_8_CrossFrontendEquivalence_LocksHarnessAtSingleFrontend"/>).
/// When Phase 5a Rego frontend lands, a new test fixture
/// <c>JsonRegoCrossEquivalenceTests : CrossFrontendEquivalenceTestBase&lt;JsonDocument, RegoDocument&gt;</c>
/// supplies its own adapters and the matrix expands automatically.
/// </para>
/// <para>
/// The matrix is defined by overriding <see cref="LogicalFixtureNames"/>. Each name is a
/// logical concept the conformance suite expects every frontend to ship; the equivalence
/// guarantee is that all participating frontends translate to byte-identical canonical IRs.
/// </para>
/// </remarks>
public abstract class CrossFrontendEquivalenceTestBase<TDocumentA, TDocumentB>
    where TDocumentA : class
    where TDocumentB : class
{
    /// <summary>Creates the adapter for frontend A.</summary>
    /// <returns>A non-null adapter.</returns>
    protected abstract IConformanceFrontendAdapter<TDocumentA> CreateAdapterA();

    /// <summary>Creates the adapter for frontend B.</summary>
    /// <returns>A non-null adapter.</returns>
    protected abstract IConformanceFrontendAdapter<TDocumentB> CreateAdapterB();

    /// <summary>
    /// Gets the logical fixture names the equivalence test runs against. The default set is
    /// the canonical cross-equivalence fixture name, which every frontend MUST ship. Frontend
    /// authors override to add additional logical names (e.g. complex policies that exercise
    /// each combinator).
    /// </summary>
    /// <returns>The logical fixture names.</returns>
    protected virtual IEnumerable<string> LogicalFixtureNames()
    {
        yield return AssemblyStrings.FixtureCrossEquivalenceCanonical;
    }

    /// <summary>
    /// Asserts that frontend A and frontend B translate every logical fixture in
    /// <see cref="LogicalFixtureNames"/> into byte-identical canonical IRs.
    /// </summary>
    [Test]
    [Category(AssemblyStrings.CategoryConformanceCrossFrontend)]
    public void CrossFrontend_Equivalence_AllLogicalFixturesProduceEqualIrs()
    {
        IConformanceFrontendAdapter<TDocumentA> a = CreateAdapterA();
        IConformanceFrontendAdapter<TDocumentB> b = CreateAdapterB();

        foreach (string logicalName in LogicalFixtureNames())
        {
            TDocumentA? docA = a.LoadFixture(logicalName);
            TDocumentB? docB = b.LoadFixture(logicalName);

            // The adapter contract guarantees a non-null parse for advertised fixtures. If
            // either side is null we fail fast — that's an adapter implementation bug, not
            // an equivalence violation.
            Assert.That(docA, Is.Not.Null, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrAdapterReturnedNullDocument, a.FrontendId, logicalName));
            Assert.That(docB, Is.Not.Null, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrAdapterReturnedNullDocument, b.FrontendId, logicalName));

            TrustPolicyTranslationResult resultA = a.Translate(docA!, new TrustPolicyTranslationContext());
            TrustPolicyTranslationResult resultB = b.Translate(docB!, new TrustPolicyTranslationContext());

            Assert.That(resultA.IsSuccess, Is.True, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrCrossFrontendFixtureFailedFormat, a.FrontendId, logicalName, string.Join(AssemblyStrings.DiagnosticListSeparatorChar, resultA.Diagnostics)));
            Assert.That(resultB.IsSuccess, Is.True, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrCrossFrontendFixtureFailedFormat, b.FrontendId, logicalName, string.Join(AssemblyStrings.DiagnosticListSeparatorChar, resultB.Diagnostics)));

            string canonicalA = TrustPolicySpecSerializer.ToCanonicalJson(resultA.Spec!);
            string canonicalB = TrustPolicySpecSerializer.ToCanonicalJson(resultB.Spec!);

            Assert.That(canonicalB, Is.EqualTo(canonicalA), () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrCrossFrontendDriftFormat, a.FrontendId, b.FrontendId, logicalName, canonicalA, canonicalB));
        }
    }
}
