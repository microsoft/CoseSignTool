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
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    [TestClass]
    public class CommandHandlingTests
    {

        [TestMethod]
        public void SetAllOptionTypesDashSpace()
        {
            string[] args = { "-PfxCertificate", "fake.pfx", "-Payload", @"c:\some.file", "-EmbedPayload", "-sf", @"c:\another.file" };
            var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string badArg);
            Assert.IsNull(badArg, "badArg should be null.");
            var cmd1 = new SignCommand();
            cmd1.ApplyOptions(provider);
            Assert.AreEqual("fake.pfx", cmd1.PfxCertificate);
            Assert.AreEqual(@"c:\some.file", cmd1.Payload);
            Assert.AreEqual(true, cmd1.EmbedPayload);

            string[] args2 = { "-Payload", @"c:\some.file", "-X509RootFiles", "asd.cer, wer.cer, rtg.cer, xcv.cer, 234.cer", "-sf", @"c:\another.file" };
            var provider2 = CoseCommand.LoadCommandLineArgs(args2, ValidateCommand.Options, out badArg);
            Assert.IsNull(badArg, "badArg should be null.");
            var cmd2 = new ValidateCommand();
            cmd2.ApplyOptions(provider2);
            Assert.IsTrue(new string[] { "asd.cer", "wer.cer", "rtg.cer", "xcv.cer", "234.cer" }.SequenceEqual(cmd2.X509RootFiles));
        }

        [TestMethod]
        public void LoadFromAliases()
        {
            string[] args = { "-p", @"c:\some.file", "-x5", "asd.cer, wer.cer, rtg.cer, xcv.cer, 234.cer", "-sf", @"c:\another.file" };
            var provider = CoseCommand.LoadCommandLineArgs(args, ValidateCommand.Options, out string badArg);
            Assert.IsNull(badArg, "badArg should be null.");
            var cmd1 = new ValidateCommand();
            cmd1.ApplyOptions(provider);
            Assert.AreEqual(@"c:\some.file", cmd1.Payload);
            Assert.AreEqual(@"c:\another.file", cmd1.SignatureFile);
            Assert.IsTrue(new string[] { "asd.cer", "wer.cer", "rtg.cer", "xcv.cer", "234.cer" }.SequenceEqual(cmd1.X509RootFiles));
        }

        [TestMethod]
        public void SlashAndDash()
        {
            string[] args = { "/PfxCertificate", "fake.pfx", "-Payload", @"c:\some.file", "/EmbedPayload", "-sf", @"c:\another.file" };
            var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out _);
            var cmd1 = new SignCommand();
            cmd1.ApplyOptions(provider);
            Assert.AreEqual(@"c:\some.file", cmd1.Payload);
            Assert.AreEqual(true, cmd1.EmbedPayload);
            Assert.AreEqual("fake.pfx", cmd1.PfxCertificate);
        }

        [TestMethod]
        public void LoadCommandLineArgs()
        {
            string[] args = { "-PfxCertificate", "fake.pfx", "-Payload", @"c:\some.file", "-embedpayload", "-sf", @"c:\another.file" };
            var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string badArg);
            Assert.IsNull(badArg, "badArg should be null.");
            var cmd1 = new SignCommand();
            cmd1.ApplyOptions(provider);
        }

        [TestMethod]
        public void LoadCommandLineArgsWithColons()
        {
            string[] args = { "-PfxCertificate:fake.pfx", @"-Payload:c:\some.file", "-embedpayload", @"-sf:c:\another.file" };
            var provider = CoseCommand.LoadCommandLineArgs(args, SignCommand.Options, out string badArg);
            Assert.IsNull(badArg, "badArg should be null.");
            var cmd1 = new SignCommand();
            cmd1.ApplyOptions(provider);
        }

        [TestMethod]
        public void FromMainInvalid()
        {
            // no verb
            string[] args1 = { @"/pfx", "fake.pfx", @"/p", "some.file" };
            Assert.AreEqual((int)ExitCode.HelpRequested, CoseSignTool.Main(args1));

            // bad argument
            string[] args2 = { "sign", "badArg", @"/pfx", "fake.pfx", @"/p", "some.file" };
            Assert.AreEqual((int)ExitCode.UnknownArgument, CoseSignTool.Main(args2));

            // empty payload argument
            string[] args3 = { "sign", @"/pfx", "fake.pfx", @"/p", "" };
            Assert.AreEqual((int)ExitCode.MissingRequiredOption, CoseSignTool.Main(args3));

            // nonexistent payload file
            string[] args4 = { "sign", @"/pfx", "fake.pfx", @"/p", "asdfa" };
            Assert.AreEqual((int)ExitCode.FileNotFound, CoseSignTool.Main(args4));

            // invalid cert container type
            string sigFile = HelperFunctions.CreateTemporaryFile();
            string payload = HelperFunctions.CreateTemporaryFile();
            string[] args5 = { "validate", @"/x5", payload, @"/sf", sigFile };
            Assert.AreEqual((int)ExitCode.InvalidArgumentValue, CoseSignTool.Main(args5));
        }
    }
}
