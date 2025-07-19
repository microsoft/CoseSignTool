// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignUnitTests;

public class CertificateStoreHelperTests
{
    private const string DefaultStoreName = "My";
    private const StoreLocation DefaultStoreLocation = StoreLocation.CurrentUser;
    static List<X509Certificate2>? StoreCertSet;

    public CertificateStoreHelperTests()
    {
        using X509Store certStore = new X509Store(DefaultStoreName, DefaultStoreLocation);
        certStore.Open(OpenFlags.ReadOnly);
        StoreCertSet = certStore.Certificates.Take(5).ToList();
        StoreCertSet.Should().NotBeEmpty();
    }

    [TestMethod]
    public void GetCertByThumbprint()
    {
        X509Certificate2 storeCert = StoreCertSet?.First() ?? throw new ArgumentNullException();
        X509Certificate2 foundCert = CoseHandler.LookupCertificate(storeCert.Thumbprint);
        foundCert.Should().Be(storeCert);
    }
}
