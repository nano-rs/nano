// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4919: the tap relay authenticates nano-api, refuses widened or
//! unbounded taps, and (with `NANO_PIPE_VECTOR_IMAGE`) relays a real capture
//! from the pinned Vector image.

use serde_json::json;

const TOKEN: &str = "relay-test-token-0123456789abcdef0123456789";

async fn serve(vector_api: &str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = nanosiem_api::pipe_tap_relay::router(TOKEN, vector_api);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn relay_refuses_unauthenticated_widened_and_unbounded_taps() {
    // Nothing listens on this Vector address: refusals happen first.
    let relay = serve("http://127.0.0.1:9").await;
    let client = reqwest::Client::new();
    let ok_body = json!({"component":"src_parse","seconds":1,"max_events":1});
    let status = |r: reqwest::Response| r.status().as_u16();
    assert_eq!(status(client.post(format!("{relay}/v1/tap")).json(&ok_body).send().await.unwrap()), 401);
    assert_eq!(
        status(client.post(format!("{relay}/v1/tap")).bearer_auth("wrong").json(&ok_body).send().await.unwrap()),
        401
    );
    for body in [
        json!({"component":"*","seconds":1,"max_events":1}),
        json!({"component":"src_parse","seconds":61,"max_events":1}),
        json!({"component":"src_parse","seconds":1,"max_events":1001}),
    ] {
        let r = client.post(format!("{relay}/v1/tap")).bearer_auth(TOKEN).json(&body).send().await.unwrap();
        assert_eq!(status(r), 400, "{body}");
    }
    // Authenticated and valid, but Vector is unreachable: a gateway error,
    // never a hang past the window.
    let r = client.post(format!("{relay}/v1/tap")).bearer_auth(TOKEN).json(&ok_body).send().await.unwrap();
    assert_eq!(status(r), 502);
}

#[tokio::test]
async fn relay_streams_a_real_capture_from_the_pinned_image() {
    let Ok(image) = std::env::var("NANO_PIPE_VECTOR_IMAGE") else {
        eprintln!("NANO_PIPE_VECTOR_IMAGE unset; skipping");
        return;
    };
    let dir = std::env::temp_dir().join(format!("nano-relay-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("vector.toml"),
        "[api]\nenabled = true\naddress = \"0.0.0.0:8686\"\n\
         [sources.input]\ntype = \"demo_logs\"\nformat = \"json\"\ninterval = 0.05\n\
         [transforms.src_parse]\ntype = \"remap\"\ninputs = [\"input\"]\nsource = \".\"\n\
         [sinks.out]\ntype = \"blackhole\"\ninputs = [\"src_parse\"]\n",
    )
    .unwrap();
    let name = format!("nan4919-relay-{}", std::process::id());
    let run = std::process::Command::new("docker")
        .args(["run", "-d", "--rm", "--name", &name, "-p", "127.0.0.1::8686", "-v"])
        .arg(format!("{}:/c:ro", dir.display()))
        .args([&image, "--config", "/c/vector.toml"])
        .output()
        .unwrap();
    assert!(run.status.success());
    let port = String::from_utf8(
        std::process::Command::new("docker").args(["port", &name, "8686"]).output().unwrap().stdout,
    )
    .unwrap();
    let port = port.trim().rsplit(':').next().unwrap().to_string();
    let relay = serve(&format!("http://127.0.0.1:{port}")).await;
    let mut events = 0;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let r = reqwest::Client::new()
            .post(format!("{relay}/v1/tap"))
            .bearer_auth(TOKEN)
            .json(&json!({"component":"src_parse","seconds":3,"max_events":3}))
            .send()
            .await
            .unwrap();
        if r.status() == 200 {
            let body: serde_json::Value = r.json().await.unwrap();
            events = body["events"].as_array().unwrap().len();
            if events > 0 {
                break;
            }
        }
    }
    let _ = std::process::Command::new("docker").args(["rm", "-f", &name]).output();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(events, 3);
}
