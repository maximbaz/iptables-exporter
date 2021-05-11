use clap::{App, Arg};
use iptables_exporter::metrics_endpoint;
use std::net::SocketAddr;
use warp::Filter;

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
