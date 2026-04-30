// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helpers for spawning built-in provider processes through the plugin loader.

use anyhow::{anyhow, Context, Result};
use cosesigntool_plugin_api::auth::{auth_key_to_hex, generate_auth_key, AUTH_KEY_ENV_VAR};
use cosesigntool_plugin_api::client::PluginClient;
use cosesigntool_plugin_api::traits::PluginConfig;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

pub struct SpawnedProvider {
    child: Child,
    client: PluginClient,
    endpoint: PluginEndpoint,
}

impl SpawnedProvider {
    pub fn create_service(&mut self, config: PluginConfig) -> Result<String> {
        self.client
            .create_service(config)
            .context("Failed to create a signing service in the plugin loader")
    }

    pub fn sign_payload(
        &mut self,
        service_id: &str,
        payload: &[u8],
        content_type: &str,
        format: &str,
        options: PluginConfig,
    ) -> Result<Vec<u8>> {
        self.client
            .sign_payload(service_id, payload, content_type, format, options)
            .with_context(|| format!("Failed to sign payload for service '{service_id}'"))
    }

    pub fn shutdown(mut self) -> Result<()> {
        let _ = self.client.send_shutdown();
        wait_for_child_exit(&mut self.child, Duration::from_secs(2))?;
        self.endpoint.cleanup();
        Ok(())
    }
}

impl Drop for SpawnedProvider {
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

        let _ = self.client.send_shutdown();
        let _ = wait_for_child_exit(&mut self.child, Duration::from_millis(500));
        self.endpoint.cleanup();
    }
}

pub fn spawn_provider(provider_name: &str) -> Result<SpawnedProvider> {
    let auth_key = generate_auth_key();
    let endpoint = PluginEndpoint::new()?;
    endpoint.cleanup();

    let loader_path = find_loader_binary()?;
    let mut child = Command::new(&loader_path)
        .arg("--plugin")
        .arg(provider_name)
        .arg("--pipe-name")
        .arg(endpoint.pipe_name.as_str())
        .env(AUTH_KEY_ENV_VAR, auth_key_to_hex(&auth_key))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("Failed to spawn plugin loader at {}", loader_path.display()))?;

    let client = match PluginClient::connect(endpoint.pipe_name.as_str(), &auth_key) {
        Ok(client) => client,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            endpoint.cleanup();
            return Err(anyhow!(error)).with_context(|| {
                format!("Failed to connect to plugin loader pipe '{}'", endpoint.pipe_name)
            });
        }
    };

    Ok(SpawnedProvider {
        child,
        client,
        endpoint,
    })
}

fn find_loader_binary() -> Result<PathBuf> {
    let current_exe = std::env::current_exe().context("Failed to determine executable path")?;
    let exe_dir = current_exe
        .parent()
        .ok_or_else(|| anyhow!("Executable has no parent directory"))?;
    let loader_name = if cfg!(windows) {
        "cosesigntool-plugin-loader.exe"
    } else {
        "cosesigntool-plugin-loader"
    };

    let candidates = [
        exe_dir.join(loader_name),
        exe_dir.join("..").join(loader_name),
        exe_dir.join("deps").join(loader_name),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(anyhow!(
        "Could not locate {} next to {}",
        loader_name,
        current_exe.display()
    ))
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
