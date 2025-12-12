// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Xml;
using System.Xml.Linq;

namespace CoseSignTool.Output;

/// <summary>
/// XML-based output formatter.
/// </summary>
public class XmlOutputFormatter : IOutputFormatter
{
    private readonly TextWriter _output;
    private readonly List<XElement> _messages = [];

    /// <summary>
    /// Initializes a new instance of the <see cref="XmlOutputFormatter"/> class.
    /// </summary>
    /// <param name="output">The output writer (defaults to Console.Out).</param>
    public XmlOutputFormatter(TextWriter? output = null)
    {
        _output = output ?? Console.Out;
    }

    /// <inheritdoc/>
    public void WriteSuccess(string message)
    {
        _messages.Add(new XElement("Success", message));
    }

    /// <inheritdoc/>
    public void WriteError(string message)
    {
        _messages.Add(new XElement("Error", message));
    }

    /// <inheritdoc/>
    public void WriteInfo(string message)
    {
        _messages.Add(new XElement("Info", message));
    }

    /// <inheritdoc/>
    public void WriteWarning(string message)
    {
        _messages.Add(new XElement("Warning", message));
    }

    /// <inheritdoc/>
    public void WriteKeyValue(string key, string value)
    {
        _messages.Add(new XElement("KeyValue",
            new XElement("Key", key),
            new XElement("Value", value)));
    }

    /// <inheritdoc/>
    public void BeginSection(string title)
    {
        _messages.Add(new XElement("SectionStart", new XAttribute("title", title)));
    }

    /// <inheritdoc/>
    public void EndSection()
    {
        _messages.Add(new XElement("SectionEnd"));
    }

    /// <inheritdoc/>
    public void Flush()
    {
        var root = new XElement("CoseSignToolOutput", _messages);
        var doc = new XDocument(new XDeclaration("1.0", "utf-8", null), root);

        // Write to string first to avoid encoding issues with console output
        var settings = new XmlWriterSettings
        {
            Indent = true,
            IndentChars = "  ",
            OmitXmlDeclaration = false,
            Encoding = System.Text.Encoding.UTF8
        };

        using var stringWriter = new StringWriter();
        using (var writer = XmlWriter.Create(stringWriter, settings))
        {
            doc.WriteTo(writer);
        }

        _output.WriteLine(stringWriter.ToString());
    }
}