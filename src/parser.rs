use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

use crate::{constants::MAX_REASON_LEN, network::normalize_ipv4};

static RE_SSH_SUCCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Accepted (?:publickey|password) for .* from (\d+\.\d+\.\d+\.\d+)")
        .expect("valid SSH success regex")
});
static RE_SSH_FAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:Failed password|Invalid user|Disconnected from authenticating user) .* (\d+\.\d+\.\d+\.\d+)")
        .expect("valid SSH failure regex")
});
static RE_HTTP_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\d+\.\d+\.\d+\.\d+) - - \[.*?\] ".*?" ([45]\d{2})"#)
        .expect("valid HTTP access-log error regex")
});
static RE_IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\d+\.\d+\.\d+\.\d+)").expect("valid IPv4 regex"));

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogSignal {
    pub ips_found: Vec<String>,
    pub safe_ip: Option<String>,
    pub suspect: Option<SuspectSignal>,
    pub http: Option<HttpSignal>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuspectSignal {
    pub ip: String,
    pub reason: String,
    pub score_delta: u32,
    pub confidence: SignalConfidence,
    pub very_high: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpSignal {
    pub ip: String,
    pub status: u16,
    pub method: String,
    pub host: String,
    pub url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalConfidence {
    Low,
    Medium,
    High,
}

pub fn parse_log_line(line: &str, source: &str) -> LogSignal {
    let fallback_ips = extract_ipv4s(line);

    if source == "Suricata"
        && let Some(mut signal) = parse_suricata_json(line)
    {
        merge_ips(&mut signal.ips_found, fallback_ips);
        return signal;
    }

    let mut signal = LogSignal {
        ips_found: fallback_ips,
        safe_ip: None,
        suspect: None,
        http: None,
    };

    if let Some(ip) = capture_ipv4(&RE_SSH_SUCCESS, line) {
        push_unique_ip(&mut signal.ips_found, ip.clone());
        signal.safe_ip = Some(ip);
        return signal;
    }

    if let Some(ip) = capture_ipv4(&RE_SSH_FAIL, line) {
        signal.suspect = Some(SuspectSignal {
            ip,
            reason: "SSH Auth Failure".to_owned(),
            score_delta: crate::constants::SSH_FAILURE_SCORE,
            confidence: SignalConfidence::Medium,
            very_high: false,
        });
        return signal;
    }

    if let Some(captures) = RE_HTTP_ERROR.captures(line)
        && let Some(ip) = captures
            .get(1)
            .and_then(|matched| normalize_ipv4(matched.as_str()))
    {
        let status = captures
            .get(2)
            .map_or("HTTP error", |matched| matched.as_str());
        signal.suspect = Some(SuspectSignal {
            ip,
            reason: format!("HTTP {status} Error"),
            score_delta: http_error_score(status),
            confidence: SignalConfidence::Low,
            very_high: false,
        });
        return signal;
    }

    if source == "Suricata"
        && line.contains("alert")
        && let Some(ip) = signal.ips_found.first().cloned()
    {
        signal.suspect = Some(SuspectSignal {
            ip,
            reason: "IDS Alert".to_owned(),
            score_delta: crate::constants::IDS_ALERT_SCORE,
            confidence: SignalConfidence::High,
            very_high: false,
        });
    }

    signal
}

fn parse_suricata_json(line: &str) -> Option<LogSignal> {
    let value = serde_json::from_str::<Value>(line).ok()?;
    let src_ip = field_ipv4(&value, "src_ip");
    let dest_ip = field_ipv4(&value, "dest_ip");

    let mut signal = LogSignal::default();
    if let Some(ip) = &src_ip {
        push_unique_ip(&mut signal.ips_found, ip.clone());
    }
    if let Some(ip) = &dest_ip {
        push_unique_ip(&mut signal.ips_found, ip.clone());
    }

    let event_type = value
        .get("event_type")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if event_type == "alert" || value.get("alert").is_some() {
        if let Some(ip) = src_ip {
            signal.suspect = Some(SuspectSignal {
                ip,
                reason: alert_reason(&value),
                score_delta: crate::constants::IDS_ALERT_SCORE,
                confidence: SignalConfidence::High,
                very_high: false,
            });
        }
        return Some(signal);
    }

    if event_type == "http" {
        let status = value
            .get("http")
            .and_then(|http| http.get("status"))
            .and_then(Value::as_u64)
            .and_then(|status| u16::try_from(status).ok());

        if let (Some(code), Some(ip)) = (status, src_ip.clone()) {
            signal.http = Some(http_signal(&value, ip, code));
        }
    }

    Some(signal)
}

fn field_ipv4(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .and_then(normalize_ipv4)
}

fn alert_reason(value: &Value) -> String {
    let alert = value.get("alert");
    let signature = alert
        .and_then(|alert| alert.get("signature"))
        .and_then(Value::as_str)
        .unwrap_or("Suricata alert");
    let category = alert
        .and_then(|alert| alert.get("category"))
        .and_then(Value::as_str)
        .unwrap_or("uncategorized");
    let severity = alert
        .and_then(|alert| alert.get("severity"))
        .and_then(Value::as_u64)
        .map_or_else(|| "?".to_owned(), |severity| severity.to_string());

    trim_reason(format!(
        "IDS Alert: {signature} | {category} | severity {severity}"
    ))
}

fn http_signal(value: &Value, ip: String, status: u16) -> HttpSignal {
    let Some(http) = value.get("http") else {
        return HttpSignal {
            ip,
            status,
            method: "-".to_owned(),
            host: "-".to_owned(),
            url: "/".to_owned(),
        };
    };

    HttpSignal {
        ip,
        status,
        method: http
            .get("http_method")
            .or_else(|| http.get("method"))
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_owned(),
        host: http
            .get("hostname")
            .or_else(|| http.get("host"))
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_owned(),
        url: http
            .get("url")
            .or_else(|| http.get("http_url"))
            .and_then(Value::as_str)
            .unwrap_or("/")
            .to_owned(),
    }
}

fn extract_ipv4s(line: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for captures in RE_IPV4.captures_iter(line) {
        if let Some(ip) = captures
            .get(1)
            .and_then(|matched| normalize_ipv4(matched.as_str()))
        {
            push_unique_ip(&mut ips, ip);
        }
    }
    ips
}

fn capture_ipv4(regex: &Regex, line: &str) -> Option<String> {
    regex
        .captures(line)
        .and_then(|captures| captures.get(1))
        .and_then(|matched| normalize_ipv4(matched.as_str()))
}

fn push_unique_ip(ips: &mut Vec<String>, ip: String) {
    if !ips.iter().any(|existing| existing == &ip) {
        ips.push(ip);
    }
}

fn merge_ips(target: &mut Vec<String>, ips: Vec<String>) {
    for ip in ips {
        push_unique_ip(target, ip);
    }
}

fn http_error_score(status: &str) -> u32 {
    status
        .parse::<u16>()
        .map_or(crate::constants::HTTP_CLIENT_ERROR_SCORE, http_status_score)
}

const fn http_status_score(status: u16) -> u32 {
    if status >= 500 {
        crate::constants::HTTP_SERVER_ERROR_SCORE
    } else {
        crate::constants::HTTP_CLIENT_ERROR_SCORE
    }
}

fn trim_reason(reason: String) -> String {
    if reason.len() <= MAX_REASON_LEN {
        return reason;
    }

    let mut trimmed = reason
        .chars()
        .take(MAX_REASON_LEN.saturating_sub(3))
        .collect::<String>();
    trimmed.push_str("...");
    trimmed
}

#[cfg(test)]
mod tests {
    use super::parse_log_line;

    #[test]
    fn parses_ssh_success_as_safe_ip() {
        let signal = parse_log_line(
            "Jun 23 host sshd[1]: Accepted publickey for root from 8.8.8.8 port 2222 ssh2",
            "SSH",
        );

        assert_eq!(signal.safe_ip.as_deref(), Some("8.8.8.8"));
        assert!(signal.suspect.is_none());
    }

    #[test]
    fn parses_suricata_http_response_from_json() {
        let signal = parse_log_line(
            r#"{"event_type":"http","src_ip":"8.8.8.8","dest_ip":"203.0.113.10","http":{"status":404,"hostname":"example.com","url":"/wp-login.php","http_method":"GET"}}"#,
            "Suricata",
        );

        let http = signal
            .http
            .expect("Suricata HTTP metadata should be captured");
        assert_eq!(http.ip, "8.8.8.8");
        assert_eq!(http.status, 404);
        assert_eq!(http.method, "GET");
        assert_eq!(http.host, "example.com");
        assert_eq!(http.url, "/wp-login.php");
        assert!(signal.suspect.is_none());
    }

    #[test]
    fn ignores_invalid_ipv4_candidates() {
        let signal = parse_log_line(
            "Failed password for root from 999.999.999.999 port 22 ssh2",
            "SSH",
        );

        assert!(signal.ips_found.is_empty());
        assert!(signal.suspect.is_none());
    }
}
