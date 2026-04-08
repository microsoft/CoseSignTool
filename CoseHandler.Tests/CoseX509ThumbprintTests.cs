// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

[TestClass]
public class CoseX509ThumbprintTests
{

    private const string SubjectName1 = $"{nameof(CoseX509ThumbprintTests)}_Cert1";
    private const string SubjectName2 = $"{nameof(CoseX509ThumbprintTests)}_Cert2";
    private static readonly X509Certificate2 SelfSignedCert1 = TestCertificateUtils.CreateCertificate(SubjectName1); // HelperFunctions.GenerateTestCert(SubjectName1);
    private static readonly X509Certificate2 SelfSignedCert2 = TestCertificateUtils.CreateCertificate(SubjectName2); // HelperFunctions.GenerateTestCert(SubjectName2);

    [TestMethod]
    public void ConstructThumbprintDefaultAlgo()
    {
        CoseX509Thumprint th = new(SelfSignedCert1);

        SHA256.HashData(SelfSignedCert1.RawData).Should().BeEquivalentTo(th.Thumbprint.ToArray(), options => options.WithStrictOrdering());
        th.Match(SelfSignedCert1).Should().BeTrue();
        th.Match(SelfSignedCert2).Should().BeFalse();

    }

    [TestMethod]
    public void ConstructThumbprintWithAlgo()
    {
        HashAlgorithm[] algos = new HashAlgorithm[]
        {
            SHA256.Create(), SHA384.Create(), SHA512.Create()
        };

        foreach (HashAlgorithm algo in algos)
        {
            Type t = algo.GetType();
            string algName = t.DeclaringType!.Name;
            CoseX509Thumprint th = new(SelfSignedCert1, new HashAlgorithmName(algName));
            HashAlgorithm hashAlgorithm = algo;

            hashAlgorithm.ComputeHash(SelfSignedCert1.RawData).Should().BeEquivalentTo(th.Thumbprint.ToArray(), options => options.WithStrictOrdering());
            th.Match(SelfSignedCert1).Should().BeTrue();
            th.Match(SelfSignedCert2).Should().BeFalse();
        }
    }

    [TestMethod]
    [ExpectedException(typeof(CoseX509FormatException))]
    public void ConstructThumbprintWithUnsupportedAlgo()
    {
        _ = new CoseX509Thumprint(SelfSignedCert1, HashAlgorithmName.SHA3_512);
    }

    /// <summary>
    /// Validates that a single <see cref="CoseX509Thumprint"/> instance can safely call
    /// <see cref="CoseX509Thumprint.Match"/> from multiple threads concurrently without
    /// throwing <see cref="CryptographicException"/>.
    /// Regression test for https://github.com/microsoft/CoseSignTool/issues/191.
    /// </summary>
    [TestMethod]
    public void ConcurrentMatchShouldNotThrow()
    {
        // Arrange — one shared thumbprint, many threads calling Match
        CoseX509Thumprint thumbprint = new(SelfSignedCert1);
        int degreeOfParallelism = Environment.ProcessorCount * 2;
        int iterationsPerThread = 50;

        // Act & Assert — hammer Match() from many threads at once
        Action concurrentAction = () =>
        {
            Parallel.For(0, degreeOfParallelism * iterationsPerThread, new ParallelOptions { MaxDegreeOfParallelism = degreeOfParallelism }, i =>
            {
                // Alternate between matching and non-matching certs
                if (i % 2 == 0)
                {
                    thumbprint.Match(SelfSignedCert1).Should().BeTrue();
                }
                else
                {
                    thumbprint.Match(SelfSignedCert2).Should().BeFalse();
                }
            });
        };

        concurrentAction.Should().NotThrow<CryptographicException>();
    }

    /// <summary>
    /// Validates that concurrent construction of <see cref="CoseX509Thumprint"/> instances
    /// with different hash algorithms is thread-safe.
    /// Regression test for https://github.com/microsoft/CoseSignTool/issues/191.
    /// </summary>
    [TestMethod]
    public void ConcurrentConstructionAndMatchShouldNotThrow()
    {
        // Arrange
        HashAlgorithmName[] algorithms = new[] { HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512 };
        int degreeOfParallelism = Environment.ProcessorCount * 2;
        int iterationsPerThread = 30;

        // Act & Assert — create thumbprints and match from many threads
        Action concurrentAction = () =>
        {
            Parallel.For(0, degreeOfParallelism * iterationsPerThread, new ParallelOptions { MaxDegreeOfParallelism = degreeOfParallelism }, i =>
            {
                HashAlgorithmName algo = algorithms[i % algorithms.Length];
                CoseX509Thumprint thumbprint = new(SelfSignedCert1, algo);

                thumbprint.Match(SelfSignedCert1).Should().BeTrue();
                thumbprint.Match(SelfSignedCert2).Should().BeFalse();
            });
        };

        concurrentAction.Should().NotThrow<CryptographicException>();
    }
}