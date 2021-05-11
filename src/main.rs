use clap::{App, Arg};
use itertools::iproduct;
use itertools::Itertools;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::process::Command;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter};
use warp::Filter;

#[derive(Clone, EnumIter)]
enum IP {
    IPv4,
    IPv6,
}

#[derive(Clone, EnumIter, Display)]
#[strum(serialize_all = "snake_case")]
enum Table {
    Filter,
    Mangle,
    Nat,
    Raw,
    Security,
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
    let matches = App::new("iptables-exporter")
        .version("0.1.0")
        .arg(
            Arg::with_name("address")
                .short("a")
                .long("address")
                .value_name("address")
                .help("Bind address")
                .default_value("127.0.0.1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("port")
                .help("Bind port")
                .default_value("9119")
                .takes_value(true),
        )
        .get_matches();

    let address = matches.value_of("address").unwrap_or("127.0.0.1");
    let port = matches.value_of("port").unwrap_or("9119");

    let bind = format!("{}:{}", address, port);
    let bind = bind
        .parse::<SocketAddr>()
        .expect(&format!("Unable to parse bind address: {}", &bind));

    let shutdown = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for Ctrl+C");
    };
    let metrics = warp::any().map(metrics_endpoint);
    let (_, server) = warp::serve(metrics).bind_with_graceful_shutdown(bind, shutdown);

    server.await;
}

fn metrics_endpoint() -> String {
    iproduct!(IP::iter(), Table::iter())
        .map(|(ip, table)| format_metrics(&ip, parse_stats(collect_stats(&ip, &table))))
        .join("\n")
}

fn collect_stats(ip_version: &IP, table: &Table) -> String {
    let executable = match ip_version {
        IP::IPv4 => "iptables",
        IP::IPv6 => "ip6tables",
    };

    let cmd = Command::new(executable)
        .arg("-t")
        .arg(table.to_string())
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

fn format_metrics(ip_version: &IP, data: HashMap<String, (i64, i64)>) -> String {
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
