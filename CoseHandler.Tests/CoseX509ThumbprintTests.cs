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
}