use itertools::Itertools;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::fmt;
use std::process::Command;
use warp::Filter;

enum IP {
    IPv4 = 4,
    IPv6 = 6,
}

impl fmt::Display for IP {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IP::IPv4 => write!(f, "4"),
            IP::IPv6 => write!(f, "6"),
        }
    }
}

#[tokio::main]
async fn main() {
    let shutdown = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for Ctrl+C");
    };

    let metrics = warp::any().map(metrics_endpoint);
    let (_, server) =
        warp::serve(metrics).bind_with_graceful_shutdown(([172, 17, 0, 1], 9119), shutdown);

    server.await;
}

fn metrics_endpoint() -> String {
    let ipv4 = format_metrics(IP::IPv4, parse_stats(collect_stats(IP::IPv4)));
    let ipv6 = format_metrics(IP::IPv6, parse_stats(collect_stats(IP::IPv6)));
    format!("{}\n{}", ipv4, ipv6)
}

fn collect_stats(ip_version: IP) -> String {
    let executable = match ip_version {
        IP::IPv4 => "iptables",
        IP::IPv6 => "ip6tables",
    };

    let cmd = Command::new(executable)
        .arg("-xnvL")
        .output()
        .expect("failed to query iptables stats");

    String::from_utf8(cmd.stdout).expect("failed to parse stdout as string")
}

fn parse_stats(iptables: String) -> HashMap<String, (i64, i64)> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^\s*(\d+)\s+(\d+).*/\* iptables-exporter (.*) \*/")
            .expect("invalid regex");
    }

    iptables
        .lines()
        .filter(|line| line.contains("iptables-exporter"))
        .map(|line| {
            let caps = RE.captures(line).expect("unexpected line from iptables");
            (
                caps[1].parse::<i64>().expect("failed to parse packets"),
                caps[2].parse::<i64>().expect("failed to parse bytes"),
                caps[3].to_string(),
            )
        })
        .fold(HashMap::new(), |mut acc, val| {
            let entry = acc.entry(val.2).or_insert((0, 0));
            *entry = (entry.0 + val.0, entry.1 + val.1);
            acc
        })
}

fn format_metrics(ip_version: IP, data: HashMap<String, (i64, i64)>) -> String {
    let line = |measure, rule, value| {
        format!(
            r#"iptables_{}{{ip_version="{}",rule="{}"}} {}"#,
            measure, ip_version, rule, value
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
            .map(|(r, (p, _))| line("packets", r, p))
            .join("\n"),
        data.iter()
            .map(|(r, (_, b))| line("bytes", r, b))
            .join("\n"),
    )
}
