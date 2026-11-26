use std::fmt::Write as _;

use ipnet::IpNet;

use crate::bypass::{BypassList, EvadePolicy, RuleMode};

/// Generates a PAC (`FindProxyForURL`) script reflecting the configured `EvadePolicy`.
///
/// - In `RuleMode::Bypass` (default): destinations matching `bypass` rules return `DIRECT`, and
///   all other destinations return `PROXY <proxy_addr>; DIRECT`.
/// - In `RuleMode::Evade` (allowlist): destinations matching `evade` rules (and not excluded by
///   `bypass`) return `PROXY <proxy_addr>; DIRECT`, and everything else returns `DIRECT`.
pub fn generate_pac(policy: &EvadePolicy, proxy_addr: &str) -> String {
    let mut js = String::new();
    let proxy_lit = js_string(&format!("PROXY {proxy_addr}; DIRECT"));
    writeln!(js, "function FindProxyForURL(url, host) {{").unwrap();
    writeln!(js, "    var h = host.toLowerCase();").unwrap();

    match policy.mode() {
        RuleMode::Bypass => {
            if !policy.bypass().is_empty() {
                writeln!(js, "    if ({}) {{", build_match_expr(policy.bypass())).unwrap();
                writeln!(js, "        return \"DIRECT\";").unwrap();
                writeln!(js, "    }}").unwrap();
            }
            writeln!(js, "    return {proxy_lit};").unwrap();
        }
        RuleMode::Evade => {
            if !policy.bypass().is_empty() {
                writeln!(js, "    if ({}) {{", build_match_expr(policy.bypass())).unwrap();
                writeln!(js, "        return \"DIRECT\";").unwrap();
                writeln!(js, "    }}").unwrap();
            }
            if !policy.evade().is_empty() {
                writeln!(js, "    if ({}) {{", build_match_expr(policy.evade())).unwrap();
                writeln!(js, "        return {proxy_lit};").unwrap();
                writeln!(js, "    }}").unwrap();
            }
            writeln!(js, "    return \"DIRECT\";").unwrap();
        }
    }

    writeln!(js, "}}").unwrap();
    js
}

fn build_match_expr(list: &BypassList) -> String {
    let mut clauses = Vec::new();

    let mut domains: Vec<&str> = list.domains().iter().map(String::as_str).collect();
    domains.sort_unstable();
    for d in domains {
        clauses.push(format!("h === {}", js_string(d)));
    }

    let mut suffixes: Vec<&str> = list.suffixes().iter().map(String::as_str).collect();
    suffixes.sort_unstable();
    for s in suffixes {
        clauses.push(format!("shExpMatch(h, {})", js_string(&format!("*.{s}"))));
    }

    let mut tlds: Vec<&str> = list.tlds().iter().map(String::as_str).collect();
    tlds.sort_unstable();
    for t in tlds {
        clauses.push(format!(
            "(h === {} || shExpMatch(h, {}))",
            js_string(t),
            js_string(&format!("*.{t}"))
        ));
    }

    for pat in list.glob_patterns() {
        clauses.push(format!("shExpMatch(h, {})", js_string(pat)));
    }

    for net in list.nets() {
        if let IpNet::V4(v4) = net {
            clauses.push(format!(
                "isInNet(h, {}, {})",
                js_string(&v4.network().to_string()),
                js_string(&v4.netmask().to_string())
            ));
        }
    }

    if clauses.is_empty() {
        "false".to_string()
    } else {
        clauses.join(" || ")
    }
}

fn js_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bypass::BypassList;

    #[test]
    fn generates_pac_for_bypass_mode() {
        let mut bypass = BypassList::default();
        bypass.add_domain("example.com").unwrap();
        bypass.add_domain("*.internal.net").unwrap();
        bypass.add_tld("ir").unwrap();
        bypass.add_ip("10.0.0.0/8").unwrap();
        let policy = EvadePolicy::new(RuleMode::Bypass, bypass, BypassList::default());

        let pac = generate_pac(&policy, "127.0.0.1:8000");
        assert!(pac.contains("function FindProxyForURL(url, host)"));
        assert!(pac.contains("h === \"example.com\""));
        assert!(pac.contains("shExpMatch(h, \"*.internal.net\")"));
        assert!(pac.contains("shExpMatch(h, \"*.ir\")"));
        assert!(pac.contains("isInNet(h, \"10.0.0.0\", \"255.0.0.0\")"));
        assert!(pac.contains("return \"DIRECT\";"));
        assert!(pac.contains("return \"PROXY 127.0.0.1:8000; DIRECT\";"));
    }

    #[test]
    fn generates_pac_for_evade_allowlist_mode() {
        let mut evade = BypassList::default();
        evade.add_domain(".youtube.com").unwrap();
        let mut bypass = BypassList::default();
        bypass.add_ip("127.0.0.1").unwrap();
        let policy = EvadePolicy::new(RuleMode::Evade, bypass, evade);

        let pac = generate_pac(&policy, "192.168.1.5:8000");
        assert!(pac.contains("isInNet(h, \"127.0.0.1\", \"255.255.255.255\")"));
        assert!(pac.contains("h === \"youtube.com\""));
        assert!(pac.contains("shExpMatch(h, \"*.youtube.com\")"));
        assert!(pac.contains("return \"PROXY 192.168.1.5:8000; DIRECT\";"));
        assert!(pac.ends_with("    return \"DIRECT\";\n}\n"));
    }
}
