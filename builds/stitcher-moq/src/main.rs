//! stitcher-moq interop test client (Paramount).
//!
//! Built on moq-dev's 0.15 release line from crates.io (`moq-tokio` 0.19 / `moq-net` 0.3) —
//! the stack Paramount's stitcher-moq publisher and relay run since 2026-09-24 — so it can
//! offer MoQT draft-22, the Seattle interop target, and implements all six canonical test
//! cases.
//!
//! By default it offers only the MoQT (IETF) drafts the crates implement, `moqt-22` down to
//! `moqt-14`: this is an MoQT interop client, and against a moq-dev relay an offer that also
//! listed moq-lite would negotiate moq-lite and exercise nothing IETF. `MOQ_CLIENT_VERSION`
//! (comma-separated, e.g. `moq-transport-18` or `moq-lite-05`) overrides the offer.
//!
//! Honest about what moq-net can put on the wire: its consumer API resolves a path only
//! through a route someone announced, so a SUBSCRIBE for an unannounced path is answered
//! *locally* (`unroutable`) and never reaches the relay. When that happens `subscribe-error`
//! reports `# SKIP` (as moq-dev's own runner client does) instead of claiming a relay
//! REQUEST_ERROR it never saw; `subscribe-before-announce` exercises the late-announce
//! routing but, for the same reason, sends its SUBSCRIBE only after the announcement.

use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Parser;
use moq_net::origin::Route;
use moq_net::Error;
use moq_tokio::moq_net;

#[derive(Parser)]
#[command(name = "stitcher-moq-client")]
#[command(about = "MoQT interop test client (Paramount stitcher-moq, moq-net/moq-tokio)")]
struct Cli {
    /// Relay URL (https:// for WebTransport, moqt:// for raw QUIC)
    #[arg(
        short,
        long,
        env = "RELAY_URL",
        default_value = "https://localhost:4443"
    )]
    relay: String,

    /// Run a specific test case
    #[arg(short, long, env = "TESTCASE")]
    test: Option<String>,

    /// List available test cases
    #[arg(short, long)]
    list: bool,

    /// Disable TLS certificate verification.
    ///
    /// The TLS_DISABLE_VERIFY env var is translated to this flag by the container
    /// entrypoint rather than read here: the interface spec allows 0/1 values,
    /// which clap's env-bool parsing would reject.
    #[arg(long)]
    tls_disable_verify: bool,

    /// Verbose output (VERBOSE env handled by the entrypoint, as above)
    #[arg(short, long)]
    verbose: bool,
}

const TESTS: &[&str] = &[
    "setup-only",
    "announce-only",
    "publish-namespace-done",
    "subscribe-error",
    "announce-subscribe",
    "subscribe-before-announce",
];

const TEST_NAMESPACE: &str = "moq-test/interop";
const TEST_TRACK: &str = "test-track";
const NONEXISTENT_NAMESPACE: &str = "nonexistent/namespace";

/// The default offer: every MoQT draft moq-net 0.3 implements, newest first.
const IETF_VERSIONS: &[&str] = &[
    "moq-transport-22",
    "moq-transport-21",
    "moq-transport-20",
    "moq-transport-19",
    "moq-transport-18",
    "moq-transport-17",
    "moq-transport-16",
    "moq-transport-15",
    "moq-transport-14",
];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the crypto provider before any TLS machinery runs (mirrors moq-cli). Ignore
    // the error if a provider is already installed.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();

    if cli.list {
        for t in TESTS {
            println!("{}", t);
        }
        return Ok(());
    }

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter("moq_net=debug,moq_tokio=debug")
            .init();
    }

    let tests: Vec<&str> = match &cli.test {
        Some(name) => {
            if !TESTS.contains(&name.as_str()) {
                eprintln!("Unknown test: {}", name);
                std::process::exit(127);
            }
            vec![name.as_str()]
        }
        None => TESTS.to_vec(),
    };

    let relay_url = url::Url::parse(&cli.relay).context("invalid relay URL")?;

    // The offered protocol versions: MOQ_CLIENT_VERSION (comma-separated, e.g.
    // "moq-transport-18") when set, otherwise every MoQT draft (see IETF_VERSIONS).
    let offered: Vec<String> = match std::env::var("MOQ_CLIENT_VERSION") {
        Ok(v) if !v.trim().is_empty() => v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        _ => IETF_VERSIONS.iter().map(|s| s.to_string()).collect(),
    };
    let versions = offered
        .iter()
        .map(|s| {
            s.parse::<moq_net::Version>()
                .map_err(|e| anyhow::anyhow!("{}: {}", s, e))
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .context("invalid MOQ_CLIENT_VERSION")?;

    println!("TAP version 14");
    println!("# stitcher-moq-client v0.2.0 (moq-net 0.3 via moq-tokio 0.19, moq-dev 0.15 line)");
    println!("# Relay: {}", cli.relay);
    println!("# Offered: {}", offered.join(", "));
    println!("1..{}", tests.len());

    // `connect::Config` is `#[non_exhaustive]`: take the defaults and set what we own.
    let mut config = moq_tokio::connect::Config::default();
    config.version = versions;
    if cli.tls_disable_verify {
        config.tls.insecure = Some(true);
    }
    // One dial per test: a failed connect must fail the test, not be retried.
    config.once = Some(true);
    let client = config
        .init(moq_tokio::quic::Config::default())
        .context("failed to init client")?;

    let mut all_passed = true;

    for (i, test_name) in tests.iter().enumerate() {
        let num = i + 1;
        let start = Instant::now();

        let result = run_test(test_name, &client, &relay_url).await;
        let duration_ms = start.elapsed().as_millis();

        match result {
            Ok(diag) => {
                match &diag.skip {
                    Some(reason) => println!("ok {} - {} # SKIP {}", num, test_name, reason),
                    None => println!("ok {} - {}", num, test_name),
                }
                print_diagnostics(duration_ms, &diag);
            }
            Err(e) => {
                all_passed = false;
                println!("not ok {} - {}", num, test_name);
                print_failure_diagnostics(duration_ms, &format!("{:#}", e));
            }
        }
    }

    if !all_passed {
        std::process::exit(1);
    }

    Ok(())
}

#[derive(Default)]
struct Diagnostics {
    negotiated: Option<String>,
    outcome: Option<String>,
    /// Report the test as `ok … # SKIP <reason>`: nothing was exercised on the wire.
    skip: Option<String>,
}

fn print_diagnostics(duration_ms: u128, diag: &Diagnostics) {
    println!("  ---");
    println!("  duration_ms: {}", duration_ms);
    if let Some(v) = &diag.negotiated {
        println!("  negotiated: {}", v);
    }
    if let Some(o) = &diag.outcome {
        println!("  outcome: \"{}\"", o.replace('"', "\\\""));
    }
    println!("  ...");
}

fn print_failure_diagnostics(duration_ms: u128, message: &str) {
    println!("  ---");
    println!("  duration_ms: {}", duration_ms);
    println!("  message: \"{}\"", message.replace('"', "\\\""));
    println!("  ...");
}

async fn run_test(
    name: &str,
    client: &moq_tokio::Client,
    relay_url: &url::Url,
) -> anyhow::Result<Diagnostics> {
    let timeout = match name {
        "setup-only" => Duration::from_secs(2),
        "announce-only" => Duration::from_secs(2),
        "publish-namespace-done" => Duration::from_secs(2),
        "subscribe-error" => Duration::from_secs(2),
        "announce-subscribe" => Duration::from_secs(3),
        // Spec guidance is 3.5s for the flow itself; the extra headroom covers the
        // stale-announcement settle phase when the full suite runs in one process.
        "subscribe-before-announce" => Duration::from_millis(5000),
        _ => Duration::from_secs(5),
    };

    tokio::time::timeout(timeout, run_test_inner(name, client, relay_url))
        .await
        .context(format!("timeout after {}ms", timeout.as_millis()))?
}

async fn run_test_inner(
    name: &str,
    client: &moq_tokio::Client,
    relay_url: &url::Url,
) -> anyhow::Result<Diagnostics> {
    match name {
        "setup-only" => test_setup_only(client, relay_url).await,
        "announce-only" => test_announce_only(client, relay_url).await,
        "publish-namespace-done" => test_publish_namespace_done(client, relay_url).await,
        "subscribe-error" => test_subscribe_error(client, relay_url).await,
        "announce-subscribe" => test_announce_subscribe(client, relay_url).await,
        "subscribe-before-announce" => test_subscribe_before_announce(client, relay_url).await,
        _ => anyhow::bail!("unknown test: {}", name),
    }
}

/// Dial the relay once — as a publisher of `publish`, a subscriber into `subscribe`, or
/// neither — and wait until the MoQ session is established.
async fn connect(
    client: &moq_tokio::Client,
    relay_url: &url::Url,
    publish: Option<moq_net::origin::Consumer>,
    subscribe: Option<moq_net::origin::Producer>,
) -> anyhow::Result<moq_tokio::Connection> {
    let mut client = client.clone();
    if let Some(origin) = publish {
        client = client.with_publisher(origin);
    }
    if let Some(origin) = subscribe {
        client = client.with_subscriber(origin);
    }
    client
        .connect(relay_url.clone())
        .established()
        .await
        .context("failed to connect")
}

fn negotiated(connection: &moq_tokio::Connection) -> String {
    connection
        .version()
        .map(|v| v.to_string())
        .unwrap_or_else(|| "unknown".into())
}

/// Connect, complete SETUP, close gracefully.
async fn test_setup_only(
    client: &moq_tokio::Client,
    relay_url: &url::Url,
) -> anyhow::Result<Diagnostics> {
    let connection = connect(client, relay_url, None, None).await?;
    let negotiated = negotiated(&connection);
    connection.abort(Error::Cancel);

    Ok(Diagnostics {
        negotiated: Some(negotiated),
        ..Default::default()
    })
}

/// Connect, PUBLISH_NAMESPACE the test namespace, verify the session survives it.
///
/// The moq-net model has no direct PUBLISH_NAMESPACE_OK surface, but a rejected or
/// unauthorized announce errors the session, so "announce sent + session still alive
/// after a grace period" is the observable success criterion.
async fn test_announce_only(
    client: &moq_tokio::Client,
    relay_url: &url::Url,
) -> anyhow::Result<Diagnostics> {
    let origin = moq_tokio::origin::spawn();
    let broadcast = origin
        .create_broadcast(TEST_NAMESPACE)
        .context("failed to create broadcast")?;
    // On the 0.15 line a broadcast is invisible until announced.
    broadcast
        .announce(Route::default())
        .context("failed to announce")?;

    let connection = connect(client, relay_url, Some(origin.consume()), None).await?;
    let negotiated = negotiated(&connection);

    tokio::select! {
        res = connection.closed() => anyhow::bail!("session closed after announce: {:?}", res),
        _ = tokio::time::sleep(Duration::from_millis(700)) => {}
    }

    connection.abort(Error::Cancel);
    drop(broadcast);

    Ok(Diagnostics {
        negotiated: Some(negotiated),
        outcome: Some("announce accepted (session healthy)".into()),
        ..Default::default()
    })
}

/// Connect, announce, then withdraw the namespace (PUBLISH_NAMESPACE_DONE on the wire).
async fn test_publish_namespace_done(
    client: &moq_tokio::Client,
    relay_url: &url::Url,
) -> anyhow::Result<Diagnostics> {
    let origin = moq_tokio::origin::spawn();
    let broadcast = origin
        .create_broadcast(TEST_NAMESPACE)
        .context("failed to create broadcast")?;
    broadcast
        .announce(Route::default())
        .context("failed to announce")?;

    let connection = connect(client, relay_url, Some(origin.consume()), None).await?;
    let negotiated = negotiated(&connection);

    // Let the announce land.
    tokio::select! {
        res = connection.closed() => anyhow::bail!("session closed after announce: {:?}", res),
        _ = tokio::time::sleep(Duration::from_millis(500)) => {}
    }

    // Withdraw: retract the announcement, then end the broadcast.
    broadcast.unannounce();
    broadcast.finish();
    drop(broadcast);

    tokio::select! {
        res = connection.closed() => anyhow::bail!("session closed after unpublish: {:?}", res),
        _ = tokio::time::sleep(Duration::from_millis(300)) => {}
    }

    connection.abort(Error::Cancel);

    Ok(Diagnostics {
        negotiated: Some(negotiated),
        outcome: Some("namespace withdrawn cleanly".into()),
        ..Default::default()
    })
}

/// SUBSCRIBE to a nonexistent namespace/track and expect a clean per-request error
/// (REQUEST_ERROR / not-found), with the session surviving.
async fn test_subscribe_error(
    client: &moq_tokio::Client,
    relay_url: &url::Url,
) -> anyhow::Result<Diagnostics> {
    let origin = moq_tokio::origin::spawn();
    let consumer = origin.consume();

    let connection = connect(client, relay_url, None, Some(origin)).await?;
    let negotiated = negotiated(&connection);

    let mut skip = None;
    let outcome = match consumer.request_broadcast(NONEXISTENT_NAMESPACE).await {
        // No announced route covers the path, so moq-net answered without sending a
        // SUBSCRIBE: the relay's REQUEST_ERROR path was not exercised.
        Err(Error::Unroutable) => {
            skip = Some(
                "moq-net answers a request for an unannounced path locally (unroutable); no SUBSCRIBE reached the relay"
                    .to_string(),
            );
            "request answered locally: unroutable".to_string()
        }
        Err(e) => format!("request rejected cleanly: {}", e),
        Ok(broadcast) => {
            // The request resolved optimistically (a route covers the path); the track
            // subscription must then fail cleanly for this test to pass.
            let track = broadcast
                .track(TEST_TRACK)
                .context("failed to request track")?;
            match track.subscribe(None).await {
                Ok(_) => anyhow::bail!("subscription to nonexistent track succeeded"),
                Err(e) => format!("track rejected cleanly: {}", e),
            }
        }
    };

    // The error must be request-scoped: the session has to survive it.
    tokio::select! {
        res = connection.closed() => anyhow::bail!("session died instead of returning a request error: {:?}", res),
        _ = tokio::time::sleep(Duration::from_millis(300)) => {}
    }

    connection.abort(Error::Cancel);

    Ok(Diagnostics {
        negotiated: Some(negotiated),
        outcome: Some(outcome),
        skip,
    })
}

/// Two connections: publisher announces + serves a track, subscriber subscribes.
async fn test_announce_subscribe(
    client: &moq_tokio::Client,
    relay_url: &url::Url,
) -> anyhow::Result<Diagnostics> {
    // Publisher.
    let pub_origin = moq_tokio::origin::spawn();
    let broadcast = pub_origin
        .create_broadcast(TEST_NAMESPACE)
        .context("failed to create broadcast")?;
    let _track = broadcast
        .create_track(TEST_TRACK, None)
        .context("failed to create track")?;
    broadcast
        .announce(Route::default())
        .context("failed to announce")?;

    let pub_connection = connect(client, relay_url, Some(pub_origin.consume()), None)
        .await
        .context("publisher")?;

    // Give the relay time to process the announce.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Subscriber.
    let sub_origin = moq_tokio::origin::spawn();
    let sub_consumer = sub_origin.consume();
    let sub_connection = connect(client, relay_url, None, Some(sub_origin))
        .await
        .context("subscriber")?;
    let negotiated = negotiated(&sub_connection);

    // Wait for the relay to route the publisher's announcement to us, then subscribe.
    let sub_broadcast = tokio::time::timeout(
        Duration::from_millis(1500),
        sub_consumer.routed_broadcast(TEST_NAMESPACE),
    )
    .await
    .context("timeout waiting for announcement")?
    .context("broadcast never became routable")?;

    let track = sub_broadcast
        .track(TEST_TRACK)
        .context("failed to subscribe track")?;

    // SUBSCRIBE_OK: the subscription resolves with the track info once the relay
    // routes it to the publisher; a rejection resolves with the abort error.
    let _subscriber = track
        .subscribe(None)
        .await
        .context("track subscription rejected")?;

    pub_connection.abort(Error::Cancel);
    sub_connection.abort(Error::Cancel);
    drop(broadcast);

    Ok(Diagnostics {
        negotiated: Some(negotiated),
        outcome: Some("SUBSCRIBE_OK (track info received)".into()),
        ..Default::default()
    })
}

/// Subscriber connects and SUBSCRIBEs first; publisher announces 500ms later.
/// Per the test spec, either a late success or a clean REQUEST_ERROR passes —
/// the test checks graceful handling of the out-of-order flow.
async fn test_subscribe_before_announce(
    client: &moq_tokio::Client,
    relay_url: &url::Url,
) -> anyhow::Result<Diagnostics> {
    // Subscriber connects first.
    let sub_origin = moq_tokio::origin::spawn();
    let sub_consumer = sub_origin.consume();
    let sub_connection = connect(client, relay_url, None, Some(sub_origin))
        .await
        .context("subscriber")?;
    let negotiated = negotiated(&sub_connection);

    // The shared test namespace can linger at the relay for a moment after the
    // previous test's session teardown; wait for any stale announcement to clear
    // so the "before announce" ordering below is real.
    let mut announcements = sub_consumer.announced();
    let mut lingering = false;
    let settle_deadline = Instant::now() + Duration::from_millis(1500);
    loop {
        let quiet = if lingering {
            settle_deadline.saturating_duration_since(Instant::now())
        } else {
            Duration::from_millis(300)
        };
        if quiet.is_zero() {
            break;
        }
        match tokio::time::timeout(quiet, announcements.next()).await {
            Ok(Some(update)) if update.prefix.as_str() == TEST_NAMESPACE => {
                lingering = !matches!(update.kind, moq_net::announce::Kind::Retracted);
                if !lingering {
                    break; // stale announcement cleared
                }
            }
            Ok(Some(_)) => continue, // unrelated route
            Ok(None) => anyhow::bail!("origin closed while settling"),
            Err(_) => break, // quiet: nothing (more) pending
        }
    }

    // Express interest before any announcement exists: start waiting for the
    // broadcast now. The wait completes once the publisher shows up.
    let pending = sub_consumer.routed_broadcast(TEST_NAMESPACE);
    tokio::pin!(pending);

    // Confirm nothing resolves while the namespace is unpublished. (Skipped if a
    // stale announcement never cleared — the late-success outcome still applies.)
    if !lingering {
        tokio::select! {
            _ = &mut pending => anyhow::bail!("broadcast resolved before anyone announced it"),
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }

    // Publisher starts 500ms after the subscriber, per the spec.
    let pub_origin = moq_tokio::origin::spawn();
    let broadcast = pub_origin
        .create_broadcast(TEST_NAMESPACE)
        .context("failed to create broadcast")?;
    let _track = broadcast
        .create_track(TEST_TRACK, None)
        .context("failed to create track")?;
    broadcast
        .announce(Route::default())
        .context("failed to announce")?;

    let pub_connection = connect(client, relay_url, Some(pub_origin.consume()), None)
        .await
        .context("publisher")?;

    // The early subscribe must now succeed (relay routes the late announcement),
    // per the spec's "eventually succeeds once publisher announces" outcome.
    let sub_broadcast = tokio::time::timeout(Duration::from_millis(2000), &mut pending)
        .await
        .context("early subscribe never resolved after the announce")?
        .context("broadcast never became routable")?;

    let track = sub_broadcast
        .track(TEST_TRACK)
        .context("failed to subscribe track")?;
    let _subscriber = track
        .subscribe(None)
        .await
        .context("track subscription rejected")?;

    pub_connection.abort(Error::Cancel);
    sub_connection.abort(Error::Cancel);
    drop(broadcast);

    Ok(Diagnostics {
        negotiated: Some(negotiated),
        outcome: Some(
            "subscriber connected first; late announce routed to it, then SUBSCRIBE_OK (no SUBSCRIBE is sent before the announce)"
                .into(),
        ),
        ..Default::default()
    })
}
