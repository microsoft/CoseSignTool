// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Reflection;
using System.Runtime.Loader;

namespace CoseSignTool.Abstractions;

/// <summary>
/// Custom <see cref="AssemblyLoadContext"/> that isolates a plugin's dependencies in its own
/// collectible context while sharing a small, deterministic, audited set of cross-boundary
/// contract assemblies with the host.
/// </summary>
/// <remarks>
/// <para>
/// Sharing is decided by two mechanisms:
/// </para>
/// <list type="number">
///   <item>
///     <b>Framework prefix match</b> — a tiny prefix list capturing the .NET / BCL families
///     (<c>Microsoft.Extensions.*</c>, <c>Microsoft.NETCore.*</c>) plus exact framework names
///     (bare <c>System</c>, <c>mscorlib</c>, <c>netstandard</c>). True BCL <c>System.*</c>
///     assemblies (<c>System.Collections</c>, <c>System.Runtime</c>, etc.) are not listed
///     explicitly; they live in TPA and are resolved by the runtime's default-context fallback
///     when our <see cref="Load"/> returns null. This intentionally allows out-of-band NuGet
///     packages with <c>System.*</c> names (<c>System.ClientModel</c>, <c>System.Memory.Data</c>,
///     <c>System.IO.Pipelines</c>, etc.) to be loaded plugin-locally.
///   </item>
///   <item>
///     <b>Exact-name allow-list</b> — a curated <see cref="HashSet{T}"/> of repo-owned assemblies
///     whose types cross the host/plugin boundary as method parameters or return values.
///     <b>Exact-name only</b>: prefix matching here would risk false positives (e.g. a 3rd-party
///     <c>CoseSign1Plus.dll</c> being silently absorbed into the host context).
///   </item>
/// </list>
/// <para>
/// The shared decision <b>short-circuits</b> the per-plugin probing logic: if a name is
/// host-shared, <see cref="Load"/> returns <c>null</c> immediately without touching the plugin
/// directory or the <see cref="AssemblyDependencyResolver"/>. This prevents a duplicate type
/// identity from appearing if the plugin happens to ship a copy of the same DLL.
/// </para>
/// <para>
/// What is intentionally <b>NOT</b> shared (so plugins remain isolated):
/// <list type="bullet">
///   <item><c>CoseHandler</c>, <c>CoseIndirectSignature</c> — used by host and plugins via static
///         method calls only; instances do not cross the boundary.</item>
///   <item><c>CoseSign1.Certificates</c> — host downcasts use
///         <see cref="CoseSign1.Abstractions.Interfaces.ISupportsScittCompliance"/> instead of the
///         concrete <c>CertificateCoseSigningKeyProvider</c> type.</item>
///   <item><c>CoseSign1.Transparent.MST</c>, <c>CoseSign1.Certificates.AzureArtifactSigning</c> —
///         fully plugin-local. The shared library and the SDK types it extends now co-locate in
///         the plugin's ALC, removing the type-identity bug class entirely.</item>
///   <item><c>Azure.*</c> SDK packages and out-of-band <c>System.*</c> NuGet packages — only used
///         inside individual plugins.</item>
///   <item><c>Newtonsoft.Json</c> — plugins ship their own copy if they use it.</item>
/// </list>
/// </para>
/// </remarks>
public class PluginLoadContext : AssemblyLoadContext
{
    /// <summary>
    /// Framework / BCL assembly-name prefixes always sourced from the host. <c>Microsoft.Extensions.*</c>
    /// is treated as a shared family because <see cref="Microsoft.Extensions.Configuration.IConfiguration"/>
    /// (and helpers around it) cross the host/plugin boundary, and the .NET ecosystem co-versions
    /// these packages carefully.
    /// </summary>
    /// <remarks>
    /// <c>System.*</c> is intentionally NOT here — that namespace is mixed: BCL assemblies
    /// (<c>System.Collections</c>, <c>System.Runtime</c>) live in TPA and resolve naturally via the
    /// default context fallback when our <see cref="Load"/> returns null, while
    /// out-of-band NuGet packages with <c>System.*</c> names (<c>System.ClientModel</c>,
    /// <c>System.Memory.Data</c>, <c>System.IO.Pipelines</c>, etc.) are legitimate plugin-private
    /// dependencies that must be loadable from the plugin directory.
    /// </remarks>
    private static readonly string[] FrameworkPrefixes =
    {
        "Microsoft.Extensions.",
        "Microsoft.NETCore.",
    };

    /// <summary>
    /// Bare framework assembly names (no trailing dot) that must be sourced from the host.
    /// Exact-name match — bare <c>"System"</c> would otherwise collide with anything starting
    /// with the letters S-y-s-t-e-m.
    /// </summary>
    private static readonly IReadOnlySet<string> FrameworkExactNames =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "System",
            "mscorlib",
            "netstandard",
            "WindowsBase",
            "Microsoft.CSharp",
            "Microsoft.VisualBasic",
        };

    /// <summary>
    /// Repo-curated cross-boundary contract assemblies. Exact-name match only.
    /// </summary>
    /// <remarks>
    /// Adding to this list expands the host/plugin shared-type surface — review carefully. Each
    /// entry must justify itself with a concrete type that crosses the host/plugin boundary as a
    /// method parameter, return value, generic argument, or interface implementation.
    /// </remarks>
    private static readonly IReadOnlySet<string> SharedAssemblies =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // Plugin contracts: ICoseSignToolPlugin, IPluginCommand, ICertificateProviderPlugin,
            // IPluginLogger, PluginExitCode, CoseHeaderHelper, CoseHeaderDto<T>.
            "CoseSignTool.Abstractions",

            // Cose contracts: ICoseSigningKeyProvider (returned by ICertificateProviderPlugin),
            // ISupportsScittCompliance (host capability check on plugin-returned providers).
            "CoseSign1.Abstractions",

            // ICoseHeaderExtender flows out of CoseHeaderHelper.CreateHeaderExtender (which lives
            // in CoseSignTool.Abstractions) and is consumed by plugin signing commands. Both sides
            // must agree on the interface's type identity.
            "CoseSign1.Headers",
        };

    private readonly AssemblyDependencyResolver dependencyResolver;
    private readonly string pluginDirectory;

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginLoadContext"/> class.
    /// </summary>
    /// <param name="pluginPath">The path to the main plugin assembly.</param>
    /// <param name="pluginDirectory">The directory containing the plugin and its dependencies.</param>
    public PluginLoadContext(string pluginPath, string pluginDirectory) : base(isCollectible: true)
    {
        this.dependencyResolver = new AssemblyDependencyResolver(pluginPath);
        this.pluginDirectory = pluginDirectory;
    }

    /// <summary>
    /// Determines whether the assembly with the specified simple name should be sourced from the
    /// host <see cref="AssemblyLoadContext"/> rather than loaded plugin-locally.
    /// </summary>
    /// <param name="assemblyName">The simple assembly name (e.g. <c>"CoseSign1.Abstractions"</c>).</param>
    /// <returns><c>true</c> when the host owns this assembly; <c>false</c> otherwise.</returns>
    /// <remarks>
    /// Public so test code can verify the contract without reflection. The decision is two-tier:
    /// (1) framework prefix or exact framework name, (2) repo-curated exact-name allow-list.
    /// Prefix matching is intentionally restricted to .NET-owned namespaces.
    /// </remarks>
    public static bool IsHostShared(string? assemblyName)
    {
        if (string.IsNullOrEmpty(assemblyName))
        {
            return false;
        }

        if (FrameworkExactNames.Contains(assemblyName) || SharedAssemblies.Contains(assemblyName))
        {
            return true;
        }

        for (int i = 0; i < FrameworkPrefixes.Length; i++)
        {
            if (assemblyName.StartsWith(FrameworkPrefixes[i], StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Loads an assembly with the specified name.
    /// </summary>
    /// <param name="assemblyName">The name of the assembly to load.</param>
    /// <returns>The loaded assembly, or <c>null</c> to delegate to the default context.</returns>
    /// <remarks>
    /// Order of operations is critical:
    /// <list type="number">
    ///   <item>If the name is host-shared, return <c>null</c> immediately. Do <b>not</b> probe the
    ///         plugin directory or the resolver — doing so risks loading a duplicate copy that
    ///         would split type identity from the host.</item>
    ///   <item>Otherwise, look in the plugin directory directly.</item>
    ///   <item>If not found there, ask the <see cref="AssemblyDependencyResolver"/>.</item>
    ///   <item>If still not found, return <c>null</c> and let the runtime fall back to the
    ///         default context (which will likely fail — by design — for plugin-private deps).</item>
    /// </list>
    /// </remarks>
    protected override Assembly? Load(AssemblyName assemblyName)
    {
        if (assemblyName.Name == null)
        {
            return null;
        }

        if (IsHostShared(assemblyName.Name))
        {
            return null;
        }

        string expectedPath = Path.Join(this.pluginDirectory, $"{assemblyName.Name}.dll");
        if (File.Exists(expectedPath))
        {
            try
            {
                return LoadFromAssemblyPath(expectedPath);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException
                                          and not StackOverflowException
                                          and not ThreadAbortException
                                          and not AccessViolationException)
            {
                Console.Error.WriteLine($"Warning: Failed to load assembly '{assemblyName.Name}' from '{expectedPath}': {ex.Message}");
            }
        }

        string? assemblyPath = this.dependencyResolver.ResolveAssemblyToPath(assemblyName);
        if (assemblyPath != null && File.Exists(assemblyPath))
        {
            try
            {
                return LoadFromAssemblyPath(assemblyPath);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException
                                          and not StackOverflowException
                                          and not ThreadAbortException
                                          and not AccessViolationException)
            {
                Console.Error.WriteLine($"Warning: Failed to load assembly '{assemblyName.Name}' from resolver path '{assemblyPath}': {ex.Message}");
            }
        }

        return null;
    }

    /// <summary>
    /// Loads an unmanaged library with the specified name.
    /// </summary>
    /// <param name="unmanagedDllName">The name of the unmanaged library.</param>
    /// <returns>A handle to the loaded library, or <see cref="IntPtr.Zero"/> if not found.</returns>
    protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
    {
        string? libraryPath = this.dependencyResolver.ResolveUnmanagedDllToPath(unmanagedDllName);
        if (libraryPath != null && File.Exists(libraryPath))
        {
            return LoadUnmanagedDllFromPath(libraryPath);
        }

        return IntPtr.Zero;
    }
}

