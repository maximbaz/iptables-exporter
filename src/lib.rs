use itertools::iproduct;
use itertools::Itertools;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::process::Command;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter};

#[derive(Clone, Display, EnumIter, Eq, Hash, PartialEq)]
enum IP {
    #[strum(serialize = "4")]
    IPv4,
    #[strum(serialize = "6")]
    IPv6,
}

#[derive(Clone, Display, EnumIter, Eq, Hash, PartialEq)]
#[strum(serialize_all = "snake_case")]
enum Table {
    Filter,
    Mangle,
    Nat,
    Raw,
    Security,
}

struct Rule {
    name: String,
    ip: IP,
    table: Table,
    stats: Stats,
}

struct Stats {
    packets: u64,
    bytes: u64,
}

impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip && self.table == other.table && self.name == other.name
    }
}

impl Eq for Rule {}

impl Hash for Rule {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip.hash(state);
        self.table.hash(state);
        self.name.hash(state);
    }
}

impl Rule {
    fn add_stats(self, other: &Self) -> Self {
        Self {
            ip: self.ip,
            table: self.table,
            name: self.name,
            stats: Stats {
                bytes: self.stats.bytes + other.stats.bytes,
                packets: self.stats.packets + other.stats.packets,
            },
        }
    }
}

pub fn metrics_endpoint() -> String {
    format_metrics(
        iproduct!(IP::iter(), Table::iter())
            .map(|(ip, table)| parse_stats(&ip, &table, collect_stats(&ip, &table)))
            .flatten()
            .fold(HashSet::new(), |mut acc, val| {
                acc.insert(match acc.get(&val) {
                    None => val,
                    Some(other) => val.add_stats(other),
                });
                acc
            }),
    )
}

fn collect_stats(ip: &IP, table: &Table) -> String {
    let executable = match ip {
        IP::IPv4 => "iptables",
        IP::IPv6 => "ip6tables",
    };

    let cmd = Command::new(executable)
        .arg("-t")
        .arg(table.to_string())
        .arg("-xnvL")
        .output()
        .expect(&format!("failed to query {} stats", executable));

    String::from_utf8(cmd.stdout).expect("failed to parse stdout as string")
}

fn parse_stats(ip: &IP, table: &Table, stats: String) -> Vec<Rule> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^\s*(\d+)\s+(\d+).*/\* iptables-exporter (.*) \*/")
            .expect("invalid regex");
    }

    stats
        .lines()
        .filter(|line| line.contains("iptables-exporter"))
        .map(|line| {
            let caps = RE.captures(line).expect("unexpected line from iptables");
            Rule {
                ip: ip.clone(),
                table: table.clone(),
                name: caps[3].to_string(),
                stats: Stats {
                    packets: caps[1].parse().expect("failed to parse packets"),
                    bytes: caps[2].parse().expect("failed to parse bytes"),
                },
            }
        })
        .collect_vec()
}

fn format_metrics(data: HashSet<Rule>) -> String {
    let line = |measure, rule: &Rule, value| {
        format!(
            r#"iptables_{}{{ip_version="{}",table="{}",rule="{}"}} {}"#,
            measure, rule.ip, rule.table, rule.name, value
        )
    };

    format!(
        "
# HELP iptables_packets Number of matched packets
# TYPE iptables_packets counter
{}

# HELP iptables_bytes Number of matched bytes
# TYPE iptables_bytes counter
{}
",
        data.iter()
            .map(|rule| line("packets", rule, rule.stats.packets))
            .join("\n"),
        data.iter()
            .map(|rule| line("bytes", rule, rule.stats.bytes))
            .join("\n"),
    )
}
