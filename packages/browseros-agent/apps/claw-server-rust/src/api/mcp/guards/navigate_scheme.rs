use crate::api::mcp::dispatch::{ToolCall, ToolGuard};
use browseros_mcp::ToolResult;
use futures_util::future::BoxFuture;
use serde_json::Value;
use tracing::warn;

const BLOCKED_SCHEMES: &[&str] = &["javascript:", "file:", "data:"];

/// Rejects navigate schemes that must never reach the CDP layer.
pub fn guard(call: &ToolCall) -> BoxFuture<'_, Option<ToolResult>> {
    Box::pin(async move {
        if call.tool().name != "navigate" {
            return None;
        }
        let url = call.raw_args.get("url").and_then(Value::as_str)?;
        // Managed mode uses the shared allowlist. Standalone keeps the upstream
        // prefix refusal and its English error text.
        if call.state.freedom.is_managed() {
            if crate::freedom::navigation_url_allowed(url) {
                return None;
            }
            warn!(
                tool = call.tool().name,
                session_id = %call.session_id,
                reason = "blocked navigate scheme",
                "cockpit tool dispatch rejected"
            );
            return Some(ToolResult::error(format!(
                "{}: 不允許這個網址配置",
                crate::freedom::CODE_SCHEME
            )));
        }
        let trimmed = url.trim();
        let scheme_end = trimmed.find(':')?;
        let scheme = trimmed[..=scheme_end].to_ascii_lowercase();
        if !BLOCKED_SCHEMES.contains(&scheme.as_str()) {
            return None;
        }
        warn!(
            tool = call.tool().name,
            session_id = %call.session_id,
            reason = "blocked navigate scheme",
            "cockpit tool dispatch rejected"
        );
        Some(ToolResult::error(format!(
            "navigate refuses {scheme} URLs; only http(s) is allowed"
        )))
    })
}

const _: ToolGuard = guard;

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ContentBlock;
    use serde_json::json;

    #[tokio::test]
    async fn rejects_trimmed_javascript_scheme_with_ts_text() -> anyhow::Result<()> {
        let call = crate::api::mcp::test_support::tool_call(
            "navigate",
            json!({ "url": "  JaVaScRiPt:alert(1)" }),
        )
        .await?;
        let result = guard(&call)
            .await
            .unwrap_or_else(|| ToolResult::error("missing"));
        let text = result.content.iter().find_map(|block| match block {
            ContentBlock::Text(text) => Some(text.text.as_str()),
            _ => None,
        });
        assert_eq!(
            text,
            Some("navigate refuses javascript: URLs; only http(s) is allowed")
        );
        Ok(())
    }

    #[tokio::test]
    async fn standalone_still_allows_chrome_and_view_source_file() -> anyhow::Result<()> {
        for url in ["chrome://settings", "view-source:file:///etc/passwd"] {
            let call =
                crate::api::mcp::test_support::tool_call("navigate", json!({ "url": url })).await?;
            assert!(
                guard(&call).await.is_none(),
                "standalone navigate must keep the upstream result for {url}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn finding3_managed_navigate_uses_the_allowlist() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let home = dir.path().join("home");
        let profile = dir.path().join("managed");
        let standalone = dir.path().join("standalone");
        tokio::fs::create_dir_all(&home).await?;
        let state = crate::AppState::new_managed_with_home(
            std::sync::Arc::new(crate::config::Config {
                server_port: 9200,
                cdp_port: 49337,
                proxy_port: None,
                resources_dir: profile.join("resources"),
                browserclaw_dir: profile,
                session_idle: std::time::Duration::from_secs(300),
                session_retention: std::time::Duration::from_secs(7_200),
                session_sweep_interval: std::time::Duration::from_secs(60),
                replay_retention_days: 7,
                dev_mode: false,
            }),
            home,
            standalone,
            std::sync::Arc::new(crate::freedom::ClosedVerifier),
        )
        .await?;
        let catalog = std::sync::Arc::new(browseros_mcp::catalog());
        let tool_index = catalog
            .iter()
            .position(|tool| tool.name == "navigate")
            .ok_or_else(|| anyhow::anyhow!("missing navigate"))?;
        for url in [
            "chrome://settings",
            "view-source:file:///etc/passwd",
            "javascript:alert(1)",
        ] {
            let call = ToolCall::new(
                catalog.clone(),
                tool_index,
                json!({ "url": url }),
                crate::ids::SessionId::new("s1"),
                None,
                None,
                tokio_util::sync::CancellationToken::new(),
                tokio_util::sync::CancellationToken::new(),
                tokio_util::sync::CancellationToken::new(),
                None,
                state.clone(),
                browseros_mcp::output_file::create_browser_output_file_access(),
            );
            let result = guard(&call)
                .await
                .unwrap_or_else(|| ToolResult::error("missing"));
            let text = result.content.iter().find_map(|block| match block {
                ContentBlock::Text(text) => Some(text.text.as_str()),
                _ => None,
            });
            assert_eq!(
                text,
                Some("freedom_scheme_denied: 不允許這個網址配置"),
                "{url}"
            );
        }
        let allowed = ToolCall::new(
            catalog,
            tool_index,
            json!({ "url": "https://example.com" }),
            crate::ids::SessionId::new("s1"),
            None,
            None,
            tokio_util::sync::CancellationToken::new(),
            tokio_util::sync::CancellationToken::new(),
            tokio_util::sync::CancellationToken::new(),
            None,
            state,
            browseros_mcp::output_file::create_browser_output_file_access(),
        );
        assert!(guard(&allowed).await.is_none());
        Ok(())
    }
}
