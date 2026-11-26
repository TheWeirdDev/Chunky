use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::OnceLock;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use ipnet::IpNet;
use url::Host;

use crate::args::Args;

/// Why a destination matched the bypass list. Used for logging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BypassReason {
    Ip(IpNet),
    Domain(String),
    Tld(String),
    GeoIp { ip: IpAddr, country: String },
}

impl fmt::Display for BypassReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(net) => write!(f, "ip {net}"),
            Self::Domain(domain) => write!(f, "domain {domain}"),
            Self::Tld(tld) => write!(f, "tld {tld}"),
            Self::GeoIp { ip, country } => write!(f, "geoip {country} ({ip})"),
        }
    }
}

/// A bypass decision: why the destination matched, and which addresses may be connected to
/// without chunking or SNI spoofing.
///
/// Domain and TLD rules cover every resolved address. IP and GeoIP rules cover only the
/// addresses that matched, so a bypassed connection never lands on an address the rules did not
/// select.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BypassMatch {
    pub reason: BypassReason,
    pub ips: Vec<IpAddr>,
}

#[cfg(feature = "geoip")]
type CountryLookup = Box<dyn Fn(IpAddr) -> Option<String> + Send + Sync>;

/// Sorted, non-overlapping address ranges, so a lookup is a binary search instead of a scan.
#[derive(Default)]
struct NetIndex {
    v4: Vec<(u32, u32, IpNet)>,
    v6: Vec<(u128, u128, IpNet)>,
}

impl NetIndex {
    fn build(nets: &[IpNet]) -> Self {
        let mut index = Self::default();
        for net in IpNet::aggregate(&nets.to_vec()) {
            match net {
                IpNet::V4(v4) => {
                    index
                        .v4
                        .push((u32::from(v4.network()), u32::from(v4.broadcast()), net))
                }
                IpNet::V6(v6) => {
                    index
                        .v6
                        .push((u128::from(v6.network()), u128::from(v6.broadcast()), net))
                }
            }
        }
        index.v4.sort_unstable_by_key(|range| range.0);
        index.v6.sort_unstable_by_key(|range| range.0);
        index
    }

    fn find(&self, ip: IpAddr) -> Option<IpNet> {
        match ip.to_canonical() {
            IpAddr::V4(ip) => find_range(&self.v4, u32::from(ip)),
            IpAddr::V6(ip) => find_range(&self.v6, u128::from(ip)),
        }
    }
}

fn find_range<T: Ord + Copy>(ranges: &[(T, T, IpNet)], value: T) -> Option<IpNet> {
    let after = ranges.partition_point(|range| range.0 <= value);
    let (_, end, net) = ranges.get(after.checked_sub(1)?)?;
    (value <= *end).then_some(*net)
}

/// How routing rules decide whether to apply DPI evasion (chunking / SNI spoofing).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RuleMode {
    /// Evade everything except destinations matching `bypass` rules.
    #[default]
    Bypass,
    /// Allowlist mode: evade only destinations matching `evade` rules (and not `bypass`).
    Evade,
}

/// Decision for a single destination: whether to apply evasion and which IPs to connect to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDecision {
    pub evade: bool,
    pub reason: Option<String>,
    pub ips: Vec<IpAddr>,
}

/// Combines `bypass` (blocklist/exclusions) and `evade` (allowlist) rule lists.
#[derive(Default)]
pub struct EvadePolicy {
    mode: RuleMode,
    bypass: BypassList,
    evade: BypassList,
}

impl EvadePolicy {
    pub fn new(mode: RuleMode, bypass: BypassList, evade: BypassList) -> Self {
        Self {
            mode,
            bypass,
            evade,
        }
    }

    #[allow(dead_code)]
    pub fn from_bypass(bypass: BypassList) -> Self {
        Self {
            mode: RuleMode::Bypass,
            bypass,
            evade: BypassList::default(),
        }
    }

    pub fn mode(&self) -> RuleMode {
        self.mode
    }

    pub fn bypass(&self) -> &BypassList {
        &self.bypass
    }

    pub fn evade(&self) -> &BypassList {
        &self.evade
    }

    pub fn is_empty(&self) -> bool {
        self.bypass.is_empty() && self.evade.is_empty() && self.mode == RuleMode::Bypass
    }

    pub fn decide(&self, host: &str, ips: &[IpAddr]) -> PolicyDecision {
        match self.mode {
            RuleMode::Bypass => {
                if let Some(found) = self.bypass.check(host, ips) {
                    PolicyDecision {
                        evade: false,
                        reason: Some(format!("bypass ({})", found.reason)),
                        ips: found.ips,
                    }
                } else {
                    PolicyDecision {
                        evade: true,
                        reason: None,
                        ips: ips.to_vec(),
                    }
                }
            }
            RuleMode::Evade => {
                if let Some(found) = self.bypass.check(host, ips) {
                    // Explicit bypass exclusion overrides allowlist.
                    return PolicyDecision {
                        evade: false,
                        reason: Some(format!("bypass ({})", found.reason)),
                        ips: found.ips,
                    };
                }
                if let Some(found) = self.evade.check(host, ips) {
                    PolicyDecision {
                        evade: true,
                        reason: Some(format!("evade ({})", found.reason)),
                        ips: found.ips,
                    }
                } else {
                    PolicyDecision {
                        evade: false,
                        reason: Some("not in evade allowlist".to_string()),
                        ips: ips.to_vec(),
                    }
                }
            }
        }
    }
}

/// Destinations that should be proxied without chunking or SNI spoofing.
#[derive(Default)]
pub struct BypassList {
    domains: HashSet<String>,
    /// Apex names of `*.example.com` / `.example.com` rules; any subdomain depth matches.
    suffixes: HashSet<String>,
    /// Other glob patterns (`?` and `*` within a single label).
    glob_patterns: Vec<String>,
    glob_set: OnceLock<GlobSet>,
    tlds: HashSet<String>,
    nets: Vec<IpNet>,
    net_index: OnceLock<NetIndex>,
    countries: HashSet<String>,
    #[cfg(feature = "geoip")]
    geoip: Option<CountryLookup>,
}

impl BypassList {
    #[allow(dead_code)]
    pub fn from_args(args: &Args) -> io::Result<Self> {
        let mut list = Self::default();
        for rule in &args.bypass_ip {
            list.add_ip(rule)?;
        }
        for rule in &args.bypass_domain {
            list.add_domain(rule)?;
        }
        for rule in &args.bypass_tld {
            list.add_tld(rule)?;
        }
        for country in &args.bypass_geoip {
            list.add_country(country)?;
        }
        if args.bypass_private {
            list.add_private_nets()?;
        }
        for path in &args.bypass_file {
            list.load_file(path)?;
        }

        if let Some(path) = &args.geoip_db {
            list.load_geoip_db(path)?;
        }
        if !list.countries.is_empty() && !list.has_geoip() {
            return Err(invalid(geoip_requirement()));
        }
        Ok(list)
    }

    pub fn finalize_geoip(&mut self, geoip_db: Option<&Path>) -> io::Result<()> {
        if let Some(path) = geoip_db {
            self.load_geoip_db(path)?;
        }
        if !self.countries.is_empty() && !self.has_geoip() {
            return Err(invalid(geoip_requirement()));
        }
        Ok(())
    }

    pub fn domains(&self) -> &HashSet<String> {
        &self.domains
    }

    pub fn suffixes(&self) -> &HashSet<String> {
        &self.suffixes
    }

    pub fn tlds(&self) -> &HashSet<String> {
        &self.tlds
    }

    pub fn nets(&self) -> &[IpNet] {
        &self.nets
    }

    pub fn glob_patterns(&self) -> &[String] {
        &self.glob_patterns
    }

    pub fn is_empty(&self) -> bool {
        !self.has_host_rules() && self.nets.is_empty() && self.countries.is_empty()
    }

    fn has_host_rules(&self) -> bool {
        !(self.domains.is_empty()
            && self.suffixes.is_empty()
            && self.glob_patterns.is_empty()
            && self.tlds.is_empty())
    }

    /// Returns the bypass decision for `host` and its resolved addresses, if any rule matches.
    ///
    /// Domain/TLD rules match `host`. IP and GeoIP rules match the addresses in `ips`, and the
    /// result lists only those, so callers connect to addresses the rules selected.
    pub fn check(&self, host: &str, ips: &[IpAddr]) -> Option<BypassMatch> {
        if self.is_empty() {
            return None;
        }
        if let Some(reason) = self.match_host(host) {
            return Some(BypassMatch {
                reason,
                ips: ips.to_vec(),
            });
        }
        let mut reason = None;
        let mut matched = Vec::new();
        for ip in ips {
            if let Some(found) = self.match_ip(*ip) {
                reason.get_or_insert(found);
                matched.push(*ip);
            }
        }
        reason.map(|reason| BypassMatch {
            reason,
            ips: matched,
        })
    }

    fn match_host(&self, host: &str) -> Option<BypassReason> {
        if !self.has_host_rules() {
            return None;
        }
        let host = normalize_host(host);
        if host.parse::<IpAddr>().is_ok() {
            return None;
        }
        if self.domains.contains(host.as_ref()) {
            return Some(BypassReason::Domain(host.into_owned()));
        }
        if !self.suffixes.is_empty() {
            if let Some(suffix) = label_suffixes(&host)
                .skip(1)
                .find(|suffix| self.suffixes.contains(*suffix))
            {
                return Some(BypassReason::Domain(format!("*.{suffix}")));
            }
        }
        if !self.glob_patterns.is_empty() {
            let matches = self.glob_set().matches(host.replace('.', "/"));
            if let Some(index) = matches.first() {
                return Some(BypassReason::Domain(self.glob_patterns[*index].clone()));
            }
        }
        if !self.tlds.is_empty() {
            if let Some(tld) = label_suffixes(&host).find(|suffix| self.tlds.contains(*suffix)) {
                return Some(BypassReason::Tld(tld.to_string()));
            }
        }
        None
    }

    fn match_ip(&self, ip: IpAddr) -> Option<BypassReason> {
        if !self.nets.is_empty() {
            let index = self.net_index.get_or_init(|| NetIndex::build(&self.nets));
            if let Some(net) = index.find(ip) {
                return Some(BypassReason::Ip(net));
            }
        }
        if !self.countries.is_empty() {
            let country = self.country_for_ip(ip)?;
            if self.countries.contains(&country) {
                return Some(BypassReason::GeoIp { ip, country });
            }
        }
        None
    }

    fn glob_set(&self) -> &GlobSet {
        self.glob_set.get_or_init(|| {
            let mut builder = GlobSetBuilder::new();
            for pattern in &self.glob_patterns {
                // Patterns were validated in `add_glob`, so this only fails if that changes.
                match build_glob(pattern) {
                    Ok(glob) => {
                        builder.add(glob);
                    }
                    Err(e) => log::error!("dropping invalid bypass pattern {pattern:?}: {e}"),
                }
            }
            builder.build().unwrap_or_else(|e| {
                log::error!("could not compile bypass patterns: {e}");
                GlobSet::empty()
            })
        })
    }

    /// Adds a single IP or a CIDR range.
    pub fn add_ip(&mut self, rule: &str) -> io::Result<()> {
        let rule = rule.trim();
        let net = if let Ok(ip) = rule.parse::<IpAddr>() {
            IpNet::from(ip)
        } else {
            rule.parse::<IpNet>()
                .map_err(|e| invalid(format!("invalid IP or CIDR {rule:?}: {e}")))?
        };
        self.nets.push(net);
        self.net_index = OnceLock::new();
        Ok(())
    }

    /// Adds an exact domain, a `*.example.com` wildcard (any subdomain depth, not the apex),
    /// `.example.com` (apex + subdomains), or a glob using `*`/`?` within one label.
    pub fn add_domain(&mut self, pattern: &str) -> io::Result<()> {
        let pattern = pattern.trim().trim_end_matches('.');
        if pattern.is_empty() {
            return Err(invalid("empty domain pattern"));
        }
        if pattern.contains(['[', ']', '{', '}']) {
            return Err(invalid(format!(
                "invalid domain pattern {pattern:?}: only `*` and `?` wildcards are supported"
            )));
        }
        let pattern = pattern.to_lowercase();

        if let Some(apex) = pattern.strip_prefix('.') {
            if apex.is_empty() || has_glob_meta(apex) {
                return Err(invalid(format!("invalid domain pattern {pattern:?}")));
            }
            let apex = normalize_domain(apex);
            self.domains.insert(apex.clone());
            self.suffixes.insert(apex);
            return Ok(());
        }
        if let Some(apex) = pattern
            .strip_prefix("*.")
            .filter(|apex| !has_glob_meta(apex))
        {
            self.suffixes.insert(normalize_domain(apex));
            return Ok(());
        }
        if has_glob_meta(&pattern) {
            return self.add_glob(&normalize_pattern(&pattern));
        }
        self.domains.insert(normalize_domain(&pattern));
        Ok(())
    }

    /// Adds a top-level domain such as `ir` or `co.uk`. Matching is on a label boundary.
    pub fn add_tld(&mut self, tld: &str) -> io::Result<()> {
        let tld = tld.trim().trim_matches('.').to_lowercase();
        if tld.is_empty() {
            return Err(invalid("empty TLD"));
        }
        if has_glob_meta(&tld) {
            return Err(invalid(format!("TLD {tld:?} must not contain wildcards")));
        }
        self.tlds.insert(normalize_domain(&tld));
        Ok(())
    }

    /// Adds a two-letter ISO country code, e.g. `IR`.
    pub fn add_country(&mut self, country: &str) -> io::Result<()> {
        let country = country.trim().to_ascii_uppercase();
        if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return Err(invalid(format!(
                "invalid country code {country:?}; expected two letters such as IR"
            )));
        }
        self.countries.insert(country);
        Ok(())
    }

    fn add_glob(&mut self, pattern: &str) -> io::Result<()> {
        build_glob(pattern)
            .map_err(|e| invalid(format!("invalid domain pattern {pattern:?}: {e}")))?;
        if !self
            .glob_patterns
            .iter()
            .any(|existing| existing == pattern)
        {
            self.glob_patterns.push(pattern.to_string());
            self.glob_set = OnceLock::new();
        }
        Ok(())
    }

    pub fn add_private_nets(&mut self) -> io::Result<()> {
        for rule in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "100.64.0.0/10",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        ] {
            self.add_ip(rule)?;
        }
        Ok(())
    }

    /// Loads rules from a file. Each line is `<type> <value>` where type is one of `ip`/`cidr`,
    /// `domain`, `tld`, `geoip`/`country` (case-insensitive). `#` starts a comment.
    pub fn load_file(&mut self, path: &Path) -> io::Result<()> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            invalid(format!(
                "could not read bypass file {}: {e}",
                path.display()
            ))
        })?;
        for (index, line) in contents.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let kind = parts.next().unwrap_or("").to_ascii_lowercase();
            let value = parts.next().unwrap_or("").trim();
            if value.is_empty() {
                return Err(invalid(format!(
                    "{}:{}: expected \"<type> <value>\"",
                    path.display(),
                    index + 1
                )));
            }
            let result = match kind.as_str() {
                "ip" | "cidr" => self.add_ip(value),
                "domain" => self.add_domain(value),
                "tld" => self.add_tld(value),
                "geoip" | "country" => self.add_country(value),
                other => Err(invalid(format!("unknown rule type {other:?}"))),
            };
            if let Err(e) = result {
                return Err(invalid(format!("{}:{}: {e}", path.display(), index + 1)));
            }
        }
        Ok(())
    }

    #[cfg(feature = "geoip")]
    fn load_geoip_db(&mut self, path: &Path) -> io::Result<()> {
        let reader = maxminddb::Reader::open_readfile(path).map_err(|e| {
            invalid(format!(
                "could not open GeoIP database {}: {e}",
                path.display()
            ))
        })?;
        self.geoip = Some(Box::new(move |ip| {
            let result = reader.lookup(ip).ok()?;
            let country: Option<String> = result
                .decode_path(&maxminddb::path!["country", "iso_code"])
                .ok()?;
            country.map(|country| country.to_ascii_uppercase())
        }));
        Ok(())
    }

    #[cfg(not(feature = "geoip"))]
    fn load_geoip_db(&mut self, _path: &Path) -> io::Result<()> {
        Err(invalid(geoip_requirement()))
    }

    #[cfg(feature = "geoip")]
    fn has_geoip(&self) -> bool {
        self.geoip.is_some()
    }

    #[cfg(not(feature = "geoip"))]
    fn has_geoip(&self) -> bool {
        false
    }

    /// MMDB lookups are an in-memory tree walk, so results are not cached.
    #[cfg(feature = "geoip")]
    fn country_for_ip(&self, ip: IpAddr) -> Option<String> {
        self.geoip.as_ref()?(ip.to_canonical())
    }

    #[cfg(not(feature = "geoip"))]
    fn country_for_ip(&self, _ip: IpAddr) -> Option<String> {
        None
    }
}

#[cfg(feature = "geoip")]
fn geoip_requirement() -> &'static str {
    "geoip bypass rules need --geoip-db pointing at a MaxMind/DB-IP country database"
}

#[cfg(not(feature = "geoip"))]
fn geoip_requirement() -> &'static str {
    "geoip bypass rules and --geoip-db are not supported in this build; rebuild with --features geoip"
}

fn build_glob(pattern: &str) -> Result<globset::Glob, globset::Error> {
    // globset only treats `/` as a separator, so labels are separated with `/` while matching.
    GlobBuilder::new(&pattern.replace('.', "/"))
        .case_insensitive(true)
        .literal_separator(true)
        .build()
}

/// `host` followed by each suffix that starts after a `.`, e.g. `a.b.c`, `b.c`, `c`.
fn label_suffixes(host: &str) -> impl Iterator<Item = &str> {
    std::iter::once(host).chain(host.match_indices('.').map(|(index, _)| &host[index + 1..]))
}

fn normalize_host(host: &str) -> Cow<'_, str> {
    let host = host.trim().trim_end_matches('.');
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_ascii() {
        return if host.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(host.to_ascii_lowercase())
        } else {
            Cow::Borrowed(host)
        };
    }
    match Host::parse(host) {
        Ok(host) => Cow::Owned(host.to_string().to_ascii_lowercase()),
        Err(_) => Cow::Owned(host.to_lowercase()),
    }
}

fn normalize_domain(domain: &str) -> String {
    normalize_host(domain).into_owned()
}

/// IDNA-normalizes each label of a glob so it matches the punycode form of the host.
fn normalize_pattern(pattern: &str) -> String {
    if pattern.is_ascii() {
        return pattern.to_ascii_lowercase();
    }
    pattern
        .split('.')
        .map(normalize_domain)
        .collect::<Vec<_>>()
        .join(".")
}

fn has_glob_meta(pattern: &str) -> bool {
    pattern.contains(['*', '?'])
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn list() -> BypassList {
        BypassList::default()
    }

    fn reason(bypass: &BypassList, host: &str, ips: &[IpAddr]) -> Option<BypassReason> {
        bypass.check(host, ips).map(|found| found.reason)
    }

    #[test]
    fn matches_exact_domains_case_insensitively() {
        let mut bypass = list();
        bypass.add_domain("Example.COM.").unwrap();
        assert_eq!(
            reason(&bypass, "example.com", &[ip("192.0.2.1")]),
            Some(BypassReason::Domain("example.com".to_string()))
        );
        assert!(reason(&bypass, "www.example.com", &[ip("192.0.2.1")]).is_none());
        assert!(reason(&bypass, "notexample.com", &[ip("192.0.2.1")]).is_none());
    }

    #[test]
    fn wildcard_matches_subdomains_but_not_the_apex() {
        let mut bypass = list();
        bypass.add_domain("*.example.com").unwrap();
        assert!(reason(&bypass, "a.example.com", &[ip("192.0.2.1")]).is_some());
        assert!(reason(&bypass, "a.b.example.com", &[ip("192.0.2.1")]).is_some());
        assert!(reason(&bypass, "example.com", &[ip("192.0.2.1")]).is_none());
        assert!(reason(&bypass, "notexample.com", &[ip("192.0.2.1")]).is_none());
    }

    #[test]
    fn leading_dot_matches_apex_and_subdomains() {
        let mut bypass = list();
        bypass.add_domain(".example.com").unwrap();
        assert!(reason(&bypass, "example.com", &[ip("192.0.2.1")]).is_some());
        assert!(reason(&bypass, "a.example.com", &[ip("192.0.2.1")]).is_some());
    }

    #[test]
    fn tld_matches_on_a_label_boundary() {
        let mut bypass = list();
        bypass.add_tld(".IR").unwrap();
        assert!(reason(&bypass, "example.ir", &[ip("192.0.2.1")]).is_some());
        assert!(reason(&bypass, "example.co.ir", &[ip("192.0.2.1")]).is_some());
        assert!(reason(&bypass, "ir", &[ip("192.0.2.1")]).is_some());
        assert!(reason(&bypass, "notir", &[ip("192.0.2.1")]).is_none());
        assert!(reason(&bypass, "example.irish", &[ip("192.0.2.1")]).is_none());
    }

    #[test]
    fn matches_ip_ranges_and_single_addresses() {
        let mut bypass = list();
        bypass.add_ip("10.0.0.0/8").unwrap();
        bypass.add_ip("2001:db8::1").unwrap();
        assert!(matches!(
            reason(&bypass, "example.com", &[ip("10.1.2.3")]),
            Some(BypassReason::Ip(_))
        ));
        assert!(matches!(
            reason(&bypass, "example.com", &[ip("2001:db8::1")]),
            Some(BypassReason::Ip(_))
        ));
        assert!(reason(&bypass, "example.com", &[ip("11.0.0.1")]).is_none());
        assert!(reason(&bypass, "example.com", &[]).is_none());
    }

    #[test]
    fn private_nets_cover_common_ranges() {
        let mut bypass = list();
        bypass.add_private_nets().unwrap();
        for address in ["192.168.1.1", "127.0.0.1", "10.1.2.3", "::1", "fe80::1"] {
            assert!(
                reason(&bypass, "local", &[ip(address)]).is_some(),
                "expected {address} to match"
            );
        }
        assert!(reason(&bypass, "public", &[ip("8.8.8.8")]).is_none());
    }

    #[test]
    fn domain_rules_take_precedence_for_the_reason() {
        let mut bypass = list();
        bypass.add_domain("example.com").unwrap();
        bypass.add_ip("192.0.2.0/24").unwrap();
        assert_eq!(
            reason(&bypass, "example.com", &[ip("192.0.2.1")]),
            Some(BypassReason::Domain("example.com".to_string()))
        );
    }

    #[test]
    fn rejects_invalid_rules() {
        let mut bypass = list();
        assert!(bypass.add_ip("999.1.1.1").is_err());
        assert!(bypass.add_domain("*[").is_err());
        assert!(bypass.add_domain("").is_err());
        assert!(bypass.add_tld("*.ir").is_err());
        assert!(bypass.add_country("IRN").is_err());
        assert!(bypass.add_country("1R").is_err());
    }

    #[test]
    fn loads_rule_file_with_comments_and_blanks() {
        let path = std::env::temp_dir().join(format!(
            "chunky-bypass-{}-{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(
            &path,
            "# comment\n\nip 10.0.0.0/8\ndomain example.com # inline\ntld ir\ngeoip cn\n",
        )
        .unwrap();
        let mut bypass = list();
        bypass.load_file(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert!(reason(&bypass, "example.com", &[ip("192.0.2.1")]).is_some());
        assert!(reason(&bypass, "other", &[ip("10.1.1.1")]).is_some());
        assert!(reason(&bypass, "example.ir", &[ip("192.0.2.1")]).is_some());
        assert!(bypass.countries.contains("CN"));
    }

    #[test]
    fn rule_file_errors_include_the_line_number() {
        let path = std::env::temp_dir().join(format!(
            "chunky-bypass-bad-{}-{}.txt",
            std::process::id(),
            line!()
        ));
        std::fs::write(&path, "ip 10.0.0.0/8\nnope value\n").unwrap();
        let mut bypass = list();
        let err = bypass.load_file(&path).unwrap_err();
        std::fs::remove_file(&path).unwrap();
        assert!(err.to_string().contains(":2:"), "unexpected error: {err}");
    }

    #[test]
    fn ip_match_only_returns_matching_addresses() {
        let mut bypass = list();
        bypass.add_ip("10.0.0.0/8").unwrap();
        let found = bypass
            .check(
                "example.com",
                &[ip("8.8.8.8"), ip("10.1.1.1"), ip("1.1.1.1")],
            )
            .unwrap();
        assert_eq!(found.ips, vec![ip("10.1.1.1")]);
    }

    #[test]
    fn domain_match_keeps_every_address() {
        let mut bypass = list();
        bypass.add_domain("example.com").unwrap();
        let ips = [ip("8.8.8.8"), ip("1.1.1.1")];
        assert_eq!(bypass.check("example.com", &ips).unwrap().ips, ips.to_vec());
    }

    #[test]
    fn net_index_handles_overlaps_and_mapped_addresses() {
        let mut bypass = list();
        for rule in ["10.0.0.0/8", "10.1.0.0/16", "192.0.2.7", "2001:db8::/32"] {
            bypass.add_ip(rule).unwrap();
        }
        for address in [
            "10.255.255.255",
            "10.1.2.3",
            "192.0.2.7",
            "2001:db8::ffff",
            "::ffff:10.0.0.1",
        ] {
            assert!(reason(&bypass, "h", &[ip(address)]).is_some(), "{address}");
        }
        for address in [
            "9.255.255.255",
            "11.0.0.0",
            "192.0.2.6",
            "192.0.2.8",
            "2001:db9::1",
        ] {
            assert!(reason(&bypass, "h", &[ip(address)]).is_none(), "{address}");
        }
    }

    #[test]
    fn wildcard_patterns_are_idna_normalized() {
        let mut bypass = list();
        bypass.add_domain("*.bücher.de").unwrap();
        bypass.add_domain("shop?.bücher.de").unwrap();
        assert!(reason(&bypass, "a.xn--bcher-kva.de", &[]).is_some());
        assert!(reason(&bypass, "a.bücher.de", &[]).is_some());
        assert!(reason(&bypass, "shop1.xn--bcher-kva.de", &[]).is_some());
    }

    #[test]
    fn glob_star_stays_within_a_label() {
        let mut bypass = list();
        bypass.add_domain("foo*.com").unwrap();
        assert!(reason(&bypass, "foobar.com", &[]).is_some());
        assert!(reason(&bypass, "foo.evil.com", &[]).is_none());
        assert!(bypass.add_domain("a{b,c}.com").is_err());
        assert!(bypass.add_domain("a[bc].com").is_err());
    }

    #[test]
    fn ipv6_literal_hosts_skip_domain_rules() {
        let mut bypass = list();
        bypass.add_tld("1").unwrap();
        assert!(reason(&bypass, "[::1]", &[ip("::1")]).is_none());
    }

    #[test]
    fn rule_file_types_are_case_insensitive() {
        let path =
            std::env::temp_dir().join(format!("chunky-bypass-case-{}.txt", std::process::id()));
        std::fs::write(&path, "IP 10.0.0.0/8\nDomain example.com\n").unwrap();
        let mut bypass = list();
        bypass.load_file(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(reason(&bypass, "example.com", &[]).is_some());
        assert!(reason(&bypass, "x", &[ip("10.0.0.1")]).is_some());
    }

    fn args(extra: &[&str]) -> Args {
        use clap::Parser;
        Args::parse_from(std::iter::once("chunky").chain(extra.iter().copied()))
    }

    #[test]
    fn from_args_builds_rules_and_private_nets() {
        let bypass = BypassList::from_args(&args(&[
            "--bypass-ip",
            "203.0.113.0/24",
            "--bypass-domain",
            "example.com,*.internal",
            "--bypass-tld",
            "ir",
            "--bypass-private",
        ]))
        .unwrap();
        assert!(reason(&bypass, "x", &[ip("203.0.113.9")]).is_some());
        assert!(reason(&bypass, "a.internal", &[]).is_some());
        assert!(reason(&bypass, "a.ir", &[]).is_some());
        assert!(reason(&bypass, "x", &[ip("192.168.0.1")]).is_some());
        assert!(reason(&bypass, "x", &[ip("8.8.8.8")]).is_none());
    }

    #[test]
    fn from_args_rejects_geoip_rules_without_a_database() {
        let err = BypassList::from_args(&args(&["--bypass-geoip", "IR"]))
            .err()
            .unwrap();
        assert!(err.to_string().contains("geoip"), "{err}");
    }

    #[test]
    fn from_args_rejects_invalid_rules() {
        assert!(BypassList::from_args(&args(&["--bypass-ip", "nope"])).is_err());
    }

    #[cfg(feature = "geoip")]
    #[test]
    fn geoip_matches_the_resolved_address() {
        let mut bypass = list();
        bypass.add_country("cn").unwrap();
        let matched = ip("192.0.2.5");
        bypass.geoip = Some(Box::new(move |address| {
            (address == matched).then(|| "CN".to_string())
        }));

        assert!(matches!(
            reason(&bypass, "example.com", &[matched]),
            Some(BypassReason::GeoIp { country, .. }) if country == "CN"
        ));
        assert!(reason(&bypass, "example.com", &[ip("192.0.2.6")]).is_none());
    }

    #[test]
    fn evade_policy_allowlist_evades_only_matching_and_honors_bypass() {
        let mut bypass = list();
        bypass.add_domain("exempt.youtube.com").unwrap();
        let mut evade = list();
        evade.add_domain(".youtube.com").unwrap();
        evade.add_ip("198.51.100.0/24").unwrap();
        let policy = EvadePolicy::new(RuleMode::Evade, bypass, evade);

        let ips = [ip("203.0.113.1")];
        let yt = policy.decide("www.youtube.com", &ips);
        assert!(yt.evade);
        assert_eq!(yt.ips, ips);

        let exempt = policy.decide("exempt.youtube.com", &ips);
        assert!(!exempt.evade);

        let other = policy.decide("example.org", &ips);
        assert!(!other.evade);

        let mixed_ips = [ip("203.0.113.1"), ip("198.51.100.5")];
        let ip_evade = policy.decide("other.org", &mixed_ips);
        assert!(ip_evade.evade);
        assert_eq!(ip_evade.ips, vec![ip("198.51.100.5")]);
    }
}
