//! Fresh joining identities require a live, authenticated leader's strong
//! membership view. A new directory alone is never permission to reuse an ID.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use scap_service::ServiceError;
use serde_json::Value;

use crate::{failure, management, management_cli, Config};

pub(crate) struct Permit {
    deadline: Instant,
}

impl Permit {
    fn new(deadline: Instant) -> Result<Self, ServiceError> {
        let permit = Self { deadline };
        permit.current()?;
        Ok(permit)
    }

    pub(crate) fn current(&self) -> Result<(), ServiceError> {
        self.current_at(Instant::now())
    }

    pub(crate) fn current_at(&self, now: Instant) -> Result<(), ServiceError> {
        if now >= self.deadline {
            return Err(failure("JOIN_EXPIRED"));
        }
        Ok(())
    }
}

pub(crate) async fn verify(
    config: &Config,
    endpoint: Option<String>,
    token: Option<String>,
) -> Result<Permit, ServiceError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let address = endpoint
        .as_deref()
        .ok_or_else(|| failure("JOIN_MANAGEMENT_URL"))
        .and_then(address)?;
    let token = token
        .filter(|token| !token.is_empty() && token.len() <= 4096)
        .ok_or_else(|| failure("JOIN_MANAGEMENT_TOKEN"))?;
    let (status, value) = management_cli::request(address, None, token, deadline)
        .await
        .map_err(|_| failure("JOIN_UNAVAILABLE"))?;
    if status != 200 {
        return Err(failure("JOIN_UNAVAILABLE"));
    }
    validate(config, &value)?;
    Permit::new(deadline)
}

fn address(text: &str) -> Result<SocketAddr, ServiceError> {
    let url = reqwest::Url::parse(text).map_err(|_| failure("JOIN_MANAGEMENT_URL"))?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "/" | management::PATH)
    {
        return Err(failure("JOIN_MANAGEMENT_URL"));
    }
    // Parsing an HTTP URL above guarantees a host and the default HTTP port.
    let host = url.host_str().unwrap();
    let ip: IpAddr = host
        .trim_matches(['[', ']'])
        .parse()
        .map_err(|_| failure("JOIN_MANAGEMENT_URL"))?;
    if !ip.is_loopback() {
        return Err(failure("JOIN_MANAGEMENT_URL"));
    }
    let port = url.port_or_known_default().unwrap();
    if port == 0 {
        return Err(failure("JOIN_MANAGEMENT_URL"));
    }
    Ok(SocketAddr::new(ip, port))
}

fn validate(config: &Config, value: &Value) -> Result<(), ServiceError> {
    let scope = &value["scope"];
    if scope["cluster_id"].as_str() != Some(format!("{:032x}", config.cluster_id).as_str())
        || scope["cell_id"].as_str() != Some(format!("{:032x}", config.cell.cell_id).as_str())
        || scope["cell_incarnation"].as_u64() != Some(config.cell.cell_incarnation)
    {
        return Err(failure("JOIN_SCOPE"));
    }
    let bootstrap =
        management::nodes(scope, "bootstrap_voters").map_err(|_| failure("JOIN_BOOTSTRAP"))?;
    let mut expected = config.bootstrap_voters.clone();
    expected.sort_unstable();
    if expected.len() != 3
        || expected.windows(2).any(|pair| pair[0] == pair[1])
        || bootstrap.len() != 3
        || bootstrap != expected
    {
        return Err(failure("JOIN_BOOTSTRAP"));
    }
    let genesis = crate::node::genesis(config, crate::config::cell_limits())?;
    if scope["genesis_sha256"].as_str() != Some(management::hex_digest(genesis.digest).as_str()) {
        return Err(failure("JOIN_GENESIS"));
    }
    let membership = &value["membership"];
    let state = management::parse_conf_state(&membership["conf_state"])
        .map_err(|_| failure("JOIN_MEMBERSHIP"))?;
    if state.voters.len() != 3 {
        return Err(failure("JOIN_MEMBERSHIP"));
    }
    let leader = membership["leader_id"]
        .as_u64()
        .ok_or_else(|| failure("JOIN_MEMBERSHIP"))?;
    let applied = membership["applied"]
        .as_u64()
        .ok_or_else(|| failure("JOIN_MEMBERSHIP"))?;
    let pending = membership["pending_conf_index"]
        .as_u64()
        .ok_or_else(|| failure("JOIN_MEMBERSHIP"))?;
    if !state.voters.contains(&leader) && !state.voters_outgoing.contains(&leader) {
        return Err(failure("JOIN_MEMBERSHIP"));
    }
    if applied == 0 || pending > applied {
        return Err(failure("JOIN_MEMBERSHIP"));
    }
    let maximum = state
        .voters
        .iter()
        .chain(&state.learners)
        .chain(&state.voters_outgoing)
        .chain(&state.learners_next)
        .max()
        .copied()
        .unwrap();
    if config.node_id <= maximum {
        return Err(failure("JOIN_ID_REUSED"));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
