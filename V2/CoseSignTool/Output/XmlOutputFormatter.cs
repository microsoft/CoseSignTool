// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Output;

using System.Xml;
using System.Xml.Linq;
using System.Diagnostics.CodeAnalysis;

/// <summary>
/// XML-based output formatter.
/// </summary>
public class XmlOutputFormatter : IOutputFormatter
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public static readonly string ElementSuccess = "Success";
        public static readonly string ElementError = "Error";
        public static readonly string ElementInfo = "Info";
        public static readonly string ElementWarning = "Warning";
        public static readonly string ElementKeyValue = "KeyValue";
        public static readonly string ElementKey = "Key";
        public static readonly string ElementValue = "Value";
        public static readonly string ElementSectionStart = "SectionStart";
        public static readonly string ElementSectionEnd = "SectionEnd";
        public static readonly string AttributeTitle = "title";
        public static readonly string RootElement = "CoseSignToolOutput";
        public static readonly string XmlVersion = "1.0";
        public static readonly string XmlEncodingUtf8 = "utf-8";
        public static readonly string IndentChars = "  ";
    }

    private readonly TextWriter Output;
    private readonly List<XElement> Messages = [];

    /// <summary>
    /// Initializes a new instance of the <see cref="XmlOutputFormatter"/> class.
    /// </summary>
    /// <param name="output">The output writer (defaults to Console.Out).</param>
    public XmlOutputFormatter(TextWriter? output = null)
    {
        Output = output ?? Console.Out;
    }

    /// <inheritdoc/>
    public void WriteSuccess(string message)
    {
        Messages.Add(new XElement(ClassStrings.ElementSuccess, message.Trim()));
    }

    /// <inheritdoc/>
    public void WriteError(string message)
    {
        Messages.Add(new XElement(ClassStrings.ElementError, message.Trim()));
    }

    /// <inheritdoc/>
    public void WriteInfo(string message)
    {
        Messages.Add(new XElement(ClassStrings.ElementInfo, message.Trim()));
    }

    /// <inheritdoc/>
    public void WriteWarning(string message)
    {
        Messages.Add(new XElement(ClassStrings.ElementWarning, message.Trim()));
    }

    /// <inheritdoc/>
    public void WriteKeyValue(string key, string value)
    {
        // Some callers include leading spaces for indentation in text output.
        // XML output should not include those formatting artifacts in element text.
        key = key.TrimStart();

        Messages.Add(new XElement(ClassStrings.ElementKeyValue,
            new XElement(ClassStrings.ElementKey, key),
            new XElement(ClassStrings.ElementValue, value)));
    }

    /// <inheritdoc/>
    public void BeginSection(string title)
    {
        Messages.Add(new XElement(ClassStrings.ElementSectionStart, new XAttribute(ClassStrings.AttributeTitle, title)));
    }

    /// <inheritdoc/>
    public void EndSection()
    {
        Messages.Add(new XElement(ClassStrings.ElementSectionEnd));
    }

    /// <inheritdoc/>
    public void WriteStructuredData<T>(T data) where T : class
    {
        // XML formatter uses message-based output
    }

    /// <inheritdoc/>
    public void Flush()
    {
        var root = new XElement(ClassStrings.RootElement, Messages);
        var doc = new XDocument(new XDeclaration(ClassStrings.XmlVersion, ClassStrings.XmlEncodingUtf8, null), root);

        // Write to string first to avoid encoding issues with console output
        var settings = new XmlWriterSettings
        {
            Indent = true,
            IndentChars = ClassStrings.IndentChars,
            OmitXmlDeclaration = false,
            Encoding = System.Text.Encoding.UTF8
        };

        using var stringWriter = new StringWriter();
        using (var writer = XmlWriter.Create(stringWriter, settings))
        {
            doc.WriteTo(writer);
        }

        Output.WriteLine(stringWriter.ToString());
    }
}