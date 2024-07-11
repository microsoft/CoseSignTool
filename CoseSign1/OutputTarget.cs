// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1;

/// <summary>
/// A general purpose writer that routes text output to a console, a Trace listener, or a host object such as a TextBox.
/// Use the static properties StdOut, StdErr, Trace, or None to get common output targets,or use the constructor to
/// specify a host object or a specific trace listener.
/// </summary>
public class OutputTarget
{
    private static readonly OutputTarget NoneInternal = new();

    /// <summary>
    /// A host UI object, such as a TextBox, that will display the output.
    /// </summary>
    public object? HostObject { get; set; }

    /// <summary>
    /// The name of the property on the <see cref="HostObject"/> that will be set with the output.
    /// </summary>
    public string? PropertyName { get; set; } = "Text";

    /// <summary>
    /// Where the console output will be written to.
    /// </summary>
    public TextWriter? ConsoleStream;

    /// <summary>
    /// A Trace stream that will be written to.
    /// </summary>
    public TraceListener? TraceChannel;

    /// <summary>
    /// Gets an OutputTarget that writes to the standard output stream.
    /// </summary>
    public static OutputTarget StdOut { get; } = new() { ConsoleStream = Console.Out };

    /// <summary>
    /// Gets an OutputTarget that writes to the standard error stream.
    /// </summary>
    public static OutputTarget StdErr { get; } = new() { ConsoleStream = Console.Error };

    /// <summary>
    /// Gest an OutputTarget that writes to the default Trace listener.
    /// </summary>
    public static OutputTarget Trace { get; set; } = new() { TraceChannel = System.Diagnostics.Trace.Listeners.Count > 0 ? System.Diagnostics.Trace.Listeners[0] : null };

    /// <summary>
    /// Gets an OutputTarget that produces no output.
    /// </summary>
    public static OutputTarget None { get; } = NoneInternal;

    /// <summary>
    /// Creates a new OutputTarget that writes to an arbitrary object such as a TextBox or a custom log object.
    /// </summary>
    /// <param name="hostObject">The object to write to.</param>
    /// <param name="propertyName">The property to receive text output.</param>
    public OutputTarget(object hostObject, string propertyName)
    {
        HostObject = hostObject;
        PropertyName = propertyName;
    }

    /// <summary>
    /// Creates a new OutputTarget that writes to a specified TraceListener.
    /// </summary>
    /// <param name="listener">The TraceListener to write to.</param>
    public OutputTarget(TraceListener listener)
    {
        TraceChannel = listener;
    }

    /// <summary>
    /// Creates an empty OutputTarget.
    /// </summary>
    public OutputTarget() {}

    /// <summary>
    /// Appends the specified text to console, trace, and/or the host object.
    /// </summary>
    /// <param name="text">The text to append.</param>
    public void Write(string text)
    {
        ConsoleStream?.Write(text);
        TraceChannel?.Write(text);
        PropertyInfo? prop = HostObject?.GetType().GetProperty(PropertyName);
        prop?.SetValue(HostObject, $"{prop.GetValue(HostObject)}{text}");
    }

    /// <summary>
    /// Appends the specified text to console, trace, and/or the host object, followed by a newline.
    /// </summary>
    /// <param name="text">The text to append.</param>
    public void WriteLine(string text)
    {
        ConsoleStream?.WriteLine(text);
        TraceChannel?.WriteLine(text);
        PropertyInfo? prop = HostObject?.GetType().GetProperty(PropertyName);
        prop?.SetValue(HostObject, $"{prop.GetValue(HostObject)}{Environment.NewLine}{text}");
    }
}
