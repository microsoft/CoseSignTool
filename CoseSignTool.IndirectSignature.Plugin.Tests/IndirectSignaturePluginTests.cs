// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.IndirectSignature.Plugin.Tests;

[TestClass]
public class IndirectSignaturePluginTests
{
    [TestMethod]
    public void Plugin_Properties_ShouldReturnCorrectValues()
    {
        // Arrange
        IndirectSignaturePlugin plugin = new IndirectSignaturePlugin();

        // Act & Assert
        Assert.AreEqual("Indirect Signature", plugin.Name);
        Assert.IsNotNull(plugin.Version);
        Assert.IsTrue(plugin.Description.Contains("indirect COSE Sign1 signature"));
        Assert.IsNotNull(plugin.Commands);
        Assert.AreEqual(2, plugin.Commands.Count());
    }

    [TestMethod]
    public void Plugin_Commands_ShouldContainExpectedCommands()
    {
        // Arrange
        IndirectSignaturePlugin plugin = new IndirectSignaturePlugin();

        // Act
        List<IPluginCommand> commands = plugin.Commands.ToList();

        // Assert
        Assert.AreEqual(2, commands.Count);
        Assert.IsTrue(commands.Any(c => c.Name == "indirect-sign"));
        Assert.IsTrue(commands.Any(c => c.Name == "indirect-verify"));
    }

    [TestMethod]
    public void Plugin_Initialize_ShouldNotThrow()
    {
        // Arrange
        IndirectSignaturePlugin plugin = new IndirectSignaturePlugin();

        // Act & Assert - Should not throw
        plugin.Initialize();
        plugin.Initialize(null);
    }

    [TestMethod]
    public void Plugin_Commands_ShouldImplementIPluginCommand()
    {
        // Arrange
        IndirectSignaturePlugin plugin = new IndirectSignaturePlugin();

        // Act & Assert
        foreach (IPluginCommand command in plugin.Commands)
        {
            Assert.IsInstanceOfType(command, typeof(IPluginCommand));
            Assert.IsNotNull(command.Name);
            Assert.IsNotNull(command.Description);
            Assert.IsNotNull(command.Usage);
            Assert.IsNotNull(command.Options);
        }
    }
}
