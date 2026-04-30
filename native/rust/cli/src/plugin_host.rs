// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Plugin host — discovers, launches, and communicates with subprocess plugins.
//!
//! The host spawns each plugin as a subprocess, passes a named-pipe endpoint via
//! `--mode pipe --pipe-name <name>`, and then exchanges 4-byte length-prefixed
//! CBOR request/response frames over that pipe.

use anyhow::{anyhow, Context, Result};
use cosesigntool_plugin_api::protocol::{self, methods, Request, Response, ResponseResult};
use cosesigntool_plugin_api::traits::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

trait PluginTransport: Read + Write + Send {}

impl<T> PluginTransport for T where T: Read + Write + Send {}

#[derive(Debug, Clone)]
struct PluginEndpoint {
    pipe_name: String,
    #[cfg(unix)]
    socket_path: PathBuf,
}

impl PluginEndpoint {
    fn new() -> Result<Self> {
        let suffix = unique_pipe_suffix();

        #[cfg(windows)]
        {
            Ok(Self {
                pipe_name: format!(r"\\.\pipe\cosesigntool-plugin-{}", suffix),
            })
        }

        #[cfg(unix)]
        {
            let socket_path = std::env::current_dir()
                .context("Failed to determine current directory for plugin socket path")?
                .join(format!(".cosesigntool-plugin-{}.sock", suffix));
            let pipe_name = socket_path.to_string_lossy().into_owned();
            Ok(Self {
                pipe_name,
                socket_path,
            })
        }
    }

    fn cleanup(&self) {
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

/// A running plugin subprocess.
pub struct PluginProcess {
    pub info: PluginInfo,
    child: Child,
    stream: Box<dyn PluginTransport>,
    endpoint: PluginEndpoint,
}

impl PluginProcess {
    /// Send a request and read the response.
    fn call(&mut self, request: &Request) -> Result<Response> {
        let method = request.method.clone();
        protocol::write_request(&mut self.stream, request).with_context(|| {
            format!("Failed to send '{}' to plugin '{}'", method, self.info.id)
        })?;

        let response = protocol::read_response(&mut self.stream).with_context(|| {
            format!("Failed to read response for '{}' from plugin '{}'", method, self.info.id)
        })?;

        if let Some(error) = response.error.as_ref() {
            anyhow::bail!(
                "Plugin '{}' error on '{}': [{}] {}",
                self.info.id,
                method,
                error.code,
                error.message
            );
        }

        Ok(response)
    }

    fn unexpected_result(&self, method: &str, result: ResponseResult) -> anyhow::Error {
        anyhow!(
            "Plugin '{}' returned an unexpected result for '{}': {:?}",
            self.info.id,
            method,
            result
        )
    }

    /// Get the certificate chain from the plugin.
    pub fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>> {
        let response = self.call(&Request::get_cert_chain(service_id))?;
        match response.result {
            ResponseResult::CertificateChain(chain) => Ok(chain.certificates),
            result => Err(self.unexpected_result(methods::GET_CERT_CHAIN, result)),
        }
    }

    /// Get the signing algorithm from the plugin.
    pub fn get_algorithm(&mut self, service_id: &str) -> Result<i64> {
        let response = self.call(&Request::get_algorithm(service_id))?;
        match response.result {
            ResponseResult::Algorithm(result) => Ok(result.algorithm),
            result => Err(self.unexpected_result(methods::GET_ALGORITHM, result)),
        }
    }

    /// Sign data using the plugin.
    pub fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>> {
        let response = self.call(&Request::sign(service_id, data.to_vec(), algorithm))?;
        match response.result {
            ResponseResult::Sign(result) => Ok(result.signature),
            result => Err(self.unexpected_result(methods::SIGN, result)),
        }
    }

    /// Create a signing service in the plugin.
    pub fn create_service(&mut self, config: &PluginConfig) -> Result<String> {
        let response = self.call(&Request::create_service(config.clone()))?;
        match response.result {
            ResponseResult::CreateService { service_id } => Ok(service_id),
            result => Err(self.unexpected_result(methods::CREATE_SERVICE, result)),
        }
    }

    /// Send shutdown and wait for the process to exit.
    pub fn shutdown(mut self) -> Result<()> {
        let _ = self.call(&Request::shutdown());
        wait_for_child_exit(&mut self.child, Duration::from_secs(2))?;
        self.endpoint.cleanup();
        Ok(())
    }

    fn abort(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.endpoint.cleanup();
    }
}

impl Drop for PluginProcess {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {
                self.endpoint.cleanup();
                return;
            }
            Ok(None) => {}
            Err(_) => {
                self.endpoint.cleanup();
                return;
            }
        }

        let _ = protocol::write_request(&mut self.stream, &Request::shutdown());
        let _ = wait_for_child_exit(&mut self.child, Duration::from_millis(500));
        self.endpoint.cleanup();
    }
}

/// The plugin registry — discovers and manages plugin subprocesses.
pub struct PluginRegistry {
    plugins: HashMap<String, PluginProcess>,
}

impl PluginRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Discover plugins from the plugins/ directory next to the executable.
    pub fn discover(&mut self) -> Result<()> {
        let plugins_dir = Self::plugins_directory()?;
        if !plugins_dir.exists() {
            tracing::debug!("No plugins directory found at {}", plugins_dir.display());
            return Ok(());
        }

        tracing::info!("Discovering plugins in {}", plugins_dir.display());

        for entry in std::fs::read_dir(&plugins_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let filename = path.file_name().and_then(|name| name.to_str()).unwrap_or("");
            if !filename.starts_with("cosesigntool-plugin-") {
                continue;
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = entry.metadata()?.permissions().mode();
                if mode & 0o111 == 0 {
                    continue;
                }
            }

            match self.launch_plugin(&path) {
                Ok(()) => tracing::info!("Loaded plugin: {}", filename),
                Err(error) => tracing::warn!("Failed to load plugin {}: {}", filename, error),
            }
        }

        Ok(())
    }

    /// Launch a plugin binary and query its capabilities.
    fn launch_plugin(&mut self, path: &Path) -> Result<()> {
        let endpoint = PluginEndpoint::new()?;
        endpoint.cleanup();

        let mut child = Command::new(path)
            .arg("--mode")
            .arg("pipe")
            .arg("--pipe-name")
            .arg(endpoint.pipe_name.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("Failed to spawn plugin: {}", path.display()))?;

        let stream = match connect_to_plugin(&mut child, &endpoint) {
            Ok(stream) => stream,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                endpoint.cleanup();
                return Err(error).with_context(|| {
                    format!("Failed to connect to plugin pipe '{}'", endpoint.pipe_name)
                });
            }
        };

        let mut plugin = PluginProcess {
            info: PluginInfo {
                id: String::new(),
                name: String::new(),
                version: String::new(),
                description: String::new(),
                capabilities: Vec::new(),
            },
            child,
            stream,
            endpoint,
        };

        let response = match plugin.call(&Request::capabilities()) {
            Ok(response) => response,
            Err(error) => {
                plugin.abort();
                return Err(error);
            }
        };

        let info = match response.result {
            ResponseResult::PluginInfo(info) => info,
            result => {
                let error = plugin.unexpected_result(methods::CAPABILITIES, result);
                plugin.abort();
                return Err(error);
            }
        };

        let plugin_id = info.id.clone();
        plugin.info = info;
        self.plugins.insert(plugin_id, plugin);
        Ok(())
    }

    /// Get a mutable reference to a plugin by ID.
    pub fn get_mut(&mut self, id: &str) -> Option<&mut PluginProcess> {
        self.plugins.get_mut(id)
    }

    /// List all discovered plugins.
    pub fn list(&self) -> Vec<&PluginInfo> {
        self.plugins.values().map(|plugin| &plugin.info).collect()
    }

    /// Find plugins that provide a specific capability.
    pub fn find_by_capability(&self, capability: PluginCapability) -> Vec<&PluginInfo> {
        self.plugins
            .values()
            .filter(|plugin| plugin.info.capabilities.contains(&capability))
            .map(|plugin| &plugin.info)
            .collect()
    }

    /// Shutdown all plugins.
    pub fn shutdown_all(self) {
        for (_, plugin) in self.plugins {
            let _ = plugin.shutdown();
        }
    }

    /// Get the plugins directory path.
    fn plugins_directory() -> Result<PathBuf> {
        let exe_dir = std::env::current_exe()
            .context("Failed to determine executable path")?
            .parent()
            .ok_or_else(|| anyhow!("Executable has no parent directory"))?
            .to_path_buf();
        Ok(exe_dir.join("plugins"))
    }
}

fn unique_pipe_suffix() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    format!("{}-{}", std::process::id(), timestamp)
}

fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn connect_to_plugin(
    child: &mut Child,
    endpoint: &PluginEndpoint,
) -> Result<Box<dyn PluginTransport>> {
    let start = Instant::now();
    let timeout = Duration::from_secs(10);
    let mut last_error: Option<std::io::Error>;

    loop {
        match try_connect_transport(endpoint) {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                last_error = Some(error);
            }
        }

        if let Some(status) = child.try_wait()? {
            let reason = last_error
                .as_ref()
                .map(|error| error.to_string())
                .unwrap_or_else(|| "plugin exited before the pipe accepted connections".into());
            return Err(anyhow!(
                "Plugin exited with status {} before pipe connection completed: {}",
                status,
                reason
            ));
        }

        if start.elapsed() >= timeout {
            if let Some(error) = last_error {
                return Err(error).with_context(|| {
                    format!("Timed out waiting for pipe '{}'", endpoint.pipe_name)
                });
            }

            return Err(anyhow!(
                "Timed out waiting for pipe '{}'",
                endpoint.pipe_name
            ));
        }

        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(windows)]
fn try_connect_transport(endpoint: &PluginEndpoint) -> std::io::Result<Box<dyn PluginTransport>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(endpoint.pipe_name.as_str())?;
    Ok(Box::new(file))
}

#[cfg(unix)]
fn try_connect_transport(endpoint: &PluginEndpoint) -> std::io::Result<Box<dyn PluginTransport>> {
    let stream = UnixStream::connect(&endpoint.socket_path)?;
    Ok(Box::new(stream))
}
