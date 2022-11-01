// ----------------------------------------------------------------------------------------
// <copyright file="CommandHandlingTests.cs" company="Microsoft">
//      Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ----------------------------------------------------------------------------------------

namespace CoseSignUnitTests
{
    using CoseSignTool;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    [TestClass]
    public class CommandHandlingTests
    {
        [TestMethod]
        public void SetAllOptionTypesDashSpace()
        {
            string[] args = { "-StoreName", "Custom", "-Payload", @"c:\some.file", "-StoreLocation", "LocalMachine", "-EmbedPayload", "-sf", @"c:\another.file" };
            var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string badArg);
            Assert.IsNull(badArg, "badArg should be null.");
            var cmd1 = new SignCommand();
            cmd1.ApplyOptions(provider);
            Assert.AreEqual("Custom", cmd1.StoreName);
            Assert.AreEqual(@"c:\some.file", cmd1.Payload);
            Assert.AreEqual(true, cmd1.EmbedPayload);
            Assert.AreEqual(StoreLocation.LocalMachine, cmd1.StoreLocation);

            string[] args2 = { "-StoreName", "Custom", "-Payload", @"c:\some.file", "-StoreLocation", "LocalMachine", "-Thumbprints", "asd, wer, rtg, xcv, 234", "-sf", @"c:\another.file" };
            var provider2 = CoseCommand.LoadCommandLineArgs(args2, ValidateCommand.Options, out badArg);
            Assert.IsNull(badArg, "badArg should be null.");
            var cmd2 = new ValidateCommand();
            cmd2.ApplyOptions(provider2);
            Assert.IsTrue(new string[] { "asd", "wer", "rtg", "xcv", "234" }.SequenceEqual(cmd2.Thumbprints));
        }

        [TestMethod]
        public void LoadFromAliases()
        {
            string[] args = { "-sn", "Custom", "-p", @"c:\some.file", "-th", "asd, wer, rtg, xcv, 234", "-sf", @"c:\another.file" };
            var provider = CoseCommand.LoadCommandLineArgs(args, ValidateCommand.Options, out string badArg);
            Assert.IsNull(badArg, "badArg should be null.");
            var cmd1 = new ValidateCommand();
            cmd1.ApplyOptions(provider);
            Assert.AreEqual("Custom", cmd1.StoreName);
            Assert.AreEqual(@"c:\some.file", cmd1.Payload);
            Assert.AreEqual(StoreLocation.CurrentUser, cmd1.StoreLocation);
            Assert.AreEqual(@"c:\another.file", cmd1.SignatureFile);
        }

        [TestMethod]
        public void SlashAndDash()
        {
            string[] args = { "/StoreName", "Custom", "-Payload", @"c:\some.file", "/StoreLocation", "LocalMachine", "/EmbedPayload", "-sf", @"c:\another.file" };
            var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out _);
            var cmd1 = new SignCommand();
            cmd1.ApplyOptions(provider);
            Assert.AreEqual("Custom", cmd1.StoreName);
            Assert.AreEqual(@"c:\some.file", cmd1.Payload);
            Assert.AreEqual(true, cmd1.EmbedPayload);
            Assert.AreEqual(StoreLocation.LocalMachine, cmd1.StoreLocation);
        }

        [TestMethod]
        public void LoadCommandLineArgs()
        {
            string[] args = { "-StoreName", "Custom", "-Payload", @"c:\some.file", "-embedpayload", "-sf", @"c:\another.file" };
            var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string badArg);
            Assert.IsNull(badArg, "badArg should be null.");
            var cmd1 = new SignCommand();
            cmd1.ApplyOptions(provider);
        }

        [TestMethod]
        public void FromMain()
        {
            // make cert files
            var cert = HelperFunctions.GenerateTestCert();
            var privateKeyCertFile = HelperFunctions.CreateTemporaryFile() + ".pfx";
            File.WriteAllBytes(privateKeyCertFile, cert.Export(X509ContentType.Pkcs12));
            var publicKeyCertFile = HelperFunctions.CreateTemporaryFile() + ".cer";
            File.WriteAllBytes(publicKeyCertFile, cert.Export(X509ContentType.Cert));

            // make payload file
            var payload = HelperFunctions.CreateTemporaryFile();
            File.WriteAllText(payload, "Payload1");

            // sign detached
            string[] args1 = { "sign", @"/pfx", privateKeyCertFile, @"/p", payload };
            Assert.AreEqual(0, CoseSignTool.Main(args1), "Detach sign failed.");

            // sign embedded
            string[] args2 = { "sign", @"/pfx", privateKeyCertFile, @"/p", payload, @"/ep" };
            Assert.AreEqual(0, CoseSignTool.Main(args2), "Embed sign failed.");

            // validate detached
            string sigFile = payload + ".cose";
            string[] args3 = { "validate", @"/x5", publicKeyCertFile, @"/sf", sigFile, @"/p", payload };
            Assert.AreEqual(0, CoseSignTool.Main(args3), "Detach validation failed.");

            // validate embedded
            sigFile = payload + ".csm";
            string[] args4 = { "validate", @"/x5", publicKeyCertFile, @"/sf", sigFile };
            Assert.AreEqual(0, CoseSignTool.Main(args4), "Embed validation failed.");

            // validate and retrieve content
            string saveFile = payload + ".saved";
            string[] args5 = { "validate", @"/x5", publicKeyCertFile, @"/sf", sigFile, "/sp", saveFile };
            Assert.AreEqual(0, CoseSignTool.Main(args5), "Detach validation with save failed.");
            Assert.AreEqual(File.ReadAllText(payload), File.ReadAllText(saveFile), "Saved content did not match payload.");
        }
    }
}
