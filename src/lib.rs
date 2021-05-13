use itertools::{iproduct, Itertools};
use lazy_static::lazy_static;
use regex::Regex;
use std::{
    cmp::Ordering,
    collections::HashSet,
    hash::{Hash, Hasher},
    process::Command,
};
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter};

#[derive(Clone, Debug, Display, EnumIter, Hash, PartialEq, Eq, PartialOrd, Ord)]
enum IP {
    #[strum(serialize = "4")]
    IPv4,
    #[strum(serialize = "6")]
    IPv6,
}

#[derive(Clone, Debug, Display, EnumIter, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[strum(serialize_all = "snake_case")]
enum Table {
    Filter,
    Mangle,
    Nat,
    Raw,
    Security,
}

#[derive(Debug)]
struct Rule {
    name: String,
    ip: IP,
    table: Table,
    stats: Stats,
}

#[derive(Debug)]
struct Stats {
    packets: u128,
    bytes: u128,
}

impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip && self.table == other.table && self.name == other.name
    }
}

impl PartialOrd for Rule {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for Rule {}

impl Ord for Rule {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.ip, &self.table, &self.name).cmp(&(&other.ip, &other.table, &other.name))
    }
}
impl Hash for Rule {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip.hash(state);
        self.table.hash(state);
        self.name.hash(state);
    }
}

trait Squash {
    fn squash(&mut self) -> Vec<Rule>;
}

impl<T: Iterator<Item = Rule>> Squash for T {
    fn squash(&mut self) -> Vec<Rule> {
        self.fold(HashSet::<Rule>::new(), |mut acc, val| {
            acc.replace(match acc.get(&val) {
                None => val,
                Some(other) => Rule {
                    ip: val.ip,
                    table: val.table,
                    name: val.name,
                    stats: Stats {
                        bytes: val.stats.bytes + other.stats.bytes,
                        packets: val.stats.packets + other.stats.packets,
                    },
                },
            });
            acc
        })
        .into_iter()
        .sorted()
        .collect()
    }
}

pub fn metrics_endpoint() -> String {
    format_metrics(
        iproduct!(IP::iter(), Table::iter())
            .map(|(ip, table)| parse_stats(&ip, &table, collect_stats(&ip, &table)))
            .flatten()
            .squash(),
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

fn format_metrics(data: Vec<Rule>) -> String {
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

#[cfg(test)]
mod test {
    use super::*;

    fn rule(ip: IP, table: Table, name: &str, packets: u128, bytes: u128) -> Rule {
        Rule {
            ip,
            table,
            name: name.to_string(),
            stats: Stats { packets, bytes },
        }
    }

    #[test]
    fn test_parse_stats_ipv4() {
        let input = "
Chain DOCKER-USER (1 references)
    pkts      bytes target     prot opt in     out     source               destination
    1149   238269 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED
35169773 6943845843 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate ESTABLISHED /* iptables-exporter established */
     254    11521 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate INVALID
      89     5328            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22 flags:0x17/0x02 ctstate NEW
    1185    66020            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:53 flags:0x17/0x02 ctstate NEW /* iptables-exporter dns */
  270644 20134629            udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:53 /* iptables-exporter dns */
  493870 33326724 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0

Chain ICMP (4 references)
    pkts      bytes target     prot opt in     out     source               destination
    1269   102634 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0            limit: up to 10/sec burst 5 mode srcip /* iptables-exporter icmp */
       0        0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* iptables-exporter drop icmp */
".to_string();

        let expected = vec![
            rule(IP::IPv4, Table::Filter, "established", 35169773, 6943845843),
            rule(IP::IPv4, Table::Filter, "dns", 1185, 66020),
            rule(IP::IPv4, Table::Filter, "dns", 270644, 20134629),
            rule(IP::IPv4, Table::Filter, "icmp", 1269, 102634),
            rule(IP::IPv4, Table::Filter, "drop icmp", 0, 0),
        ];
        assert_eq!(expected, parse_stats(&IP::IPv4, &Table::Filter, input));
    }

    #[test]
    fn test_parse_stats_ipv6() {
        let input = "
Chain INPUT (policy DROP 17 packets, 2511 bytes)
    pkts      bytes target     prot opt in     out     source               destination
     670    69680 ACCEPT     all      lo     *       ::/0                 ::/0
   50330 14370092 ACCEPT     all      *      *       ::/0                 ::/0                 ctstate RELATED,ESTABLISHED /* iptables-exporter related */
      65     5196 DROP       all      *      *       ::/0                 ::/0                 ctstate INVALID
    1899   140244 ACCEPT     tcp      *      *       ::/0                 ::/0                 tcp dpt:53 flags:0x17/0x02 ctstate NEW /* iptables-exporter dns */
   91342  8504843 ACCEPT     udp      *      *       ::/0                 ::/0                 multiport dports 53 /* iptables-exporter dns */

Chain OUTPUT (policy ACCEPT 227941 packets, 57081722 bytes)
    pkts      bytes target     prot opt in     out     source               destination
".to_string();

        let expected = vec![
            rule(IP::IPv6, Table::Filter, "related", 50330, 14370092),
            rule(IP::IPv6, Table::Filter, "dns", 1899, 140244),
            rule(IP::IPv6, Table::Filter, "dns", 91342, 8504843),
        ];
        assert_eq!(expected, parse_stats(&IP::IPv6, &Table::Filter, input));
    }

    #[test]
    fn test_rule_eq() {
        assert_eq!(
            true,
            rule(IP::IPv4, Table::Nat, "aaa", 1, 1).eq(&rule(IP::IPv4, Table::Nat, "aaa", 2, 3))
        );

        assert_eq!(
            false,
            rule(IP::IPv4, Table::Nat, "aaa", 1, 1).eq(&rule(IP::IPv6, Table::Nat, "aaa", 1, 1))
        );

        assert_eq!(
            false,
            rule(IP::IPv4, Table::Nat, "aaa", 1, 1).eq(&rule(IP::IPv4, Table::Filter, "aaa", 1, 1))
        );

        assert_eq!(
            false,
            rule(IP::IPv4, Table::Nat, "aaa", 1, 1).eq(&rule(IP::IPv4, Table::Nat, "bbb", 1, 1))
        );
    }

    #[test]
    fn test_rule_squash() {
        assert_eq!(
            vec![
                rule(IP::IPv4, Table::Filter, "bbb", 10, 250),
                rule(IP::IPv4, Table::Security, "aaa", 100, 200),
                rule(IP::IPv6, Table::Nat, "ccc", 1, 1),
            ],
            vec![
                rule(IP::IPv4, Table::Filter, "bbb", 0, 0),
                rule(IP::IPv6, Table::Nat, "ccc", 1, 1),
                rule(IP::IPv4, Table::Security, "aaa", 0, 0),
                rule(IP::IPv4, Table::Security, "aaa", 50, 120),
                rule(IP::IPv4, Table::Filter, "bbb", 10, 250),
                rule(IP::IPv4, Table::Security, "aaa", 50, 80)
            ]
            .into_iter()
            .squash()
        );
    }

    #[test]
    fn test_format_metrics() {
        let expected = r#"
# HELP iptables_packets Number of matched packets
# TYPE iptables_packets counter
iptables_packets{ip_version="4",table="filter",rule="aaa"} 10
iptables_packets{ip_version="4",table="raw",rule="bbb"} 2000
iptables_packets{ip_version="6",table="mangle",rule="ccc"} 0

# HELP iptables_bytes Number of matched bytes
# TYPE iptables_bytes counter
iptables_bytes{ip_version="4",table="filter",rule="aaa"} 70
iptables_bytes{ip_version="4",table="raw",rule="bbb"} 7000
iptables_bytes{ip_version="6",table="mangle",rule="ccc"} 17
"#;
        let rules = vec![
            rule(IP::IPv4, Table::Filter, "aaa", 10, 70),
            rule(IP::IPv4, Table::Raw, "bbb", 2000, 7000),
            rule(IP::IPv6, Table::Mangle, "ccc", 0, 17),
        ];

        assert_eq!(expected, format_metrics(rules));
    }
}
