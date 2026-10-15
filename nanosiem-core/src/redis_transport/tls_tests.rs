// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::time::Duration;

#[tokio::test]
#[ignore = "requires scripts/validate-redis-tls-transport.mjs owned TLS fixture"]
async fn verified_dragonfly_tls_rejects_invalid_peers_and_credentials() {
    assert_eq!(std::env::var("NANO_REDIS_TLS_FIXTURE").as_deref(), Ok("1"));
    let url = std::env::var("NANO_REDIS_TLS_TEST_URL").unwrap();
    let mut parsed = url::Url::parse(&url).unwrap();
    assert_eq!(parsed.scheme(), "rediss");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(parsed.username(), "nano-fixture");
    assert!(parsed.port().unwrap() > 1024);
    let ca = std::path::PathBuf::from(std::env::var_os("NANO_REDIS_TLS_TEST_CA").unwrap());
    let wrong_ca =
        std::path::PathBuf::from(std::env::var_os("NANO_REDIS_TLS_TEST_WRONG_CA").unwrap());
    async fn connect(client: Client) -> RedisResult<redis::aio::MultiplexedConnection> {
        tokio::time::timeout(
            Duration::from_secs(10),
            client.get_multiplexed_async_connection(),
        )
        .await
        .expect("fixture connection deadline")
    }
    let mut connection = connect(client_with_ca(&url, Some(&ca)).unwrap())
        .await
        .unwrap();
    let pong: String = redis::cmd("PING")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(pong, "PONG");
    let _: () = redis::cmd("SET")
        .arg("fixture:tls")
        .arg("verified")
        .query_async(&mut connection)
        .await
        .unwrap();
    let value: String = redis::cmd("GET")
        .arg("fixture:tls")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(value, "verified");
    drop(connection);

    let wrong_ca_error = connect(client_with_ca(&url, Some(&wrong_ca)).unwrap())
        .await
        .unwrap_err();
    assert!(
        wrong_ca_error.to_string().contains("UnknownIssuer"),
        "wrong CA must fail certificate verification"
    );
    // Server certificate has only the IP SAN. localhost resolves to the same
    // loopback listener, but must fail hostname validation after connecting.
    parsed.set_host(Some("localhost")).unwrap();
    let name_error = connect(client_with_ca(parsed.as_str(), Some(&ca)).unwrap())
        .await
        .unwrap_err();
    assert!(
        name_error
            .to_string()
            .contains("certificate not valid for name"),
        "wrong hostname must fail certificate verification: {name_error}"
    );
    parsed.set_host(Some("127.0.0.1")).unwrap();
    parsed
        .set_password(Some("definitely-not-the-fixture-password"))
        .unwrap();
    let password_error = connect(client_with_ca(parsed.as_str(), Some(&ca)).unwrap())
        .await
        .unwrap_err();
    assert_eq!(
        password_error.kind(),
        ErrorKind::AuthenticationFailed,
        "wrong password must fail authentication"
    );
    parsed.set_username("default").unwrap();
    parsed
        .set_password(Some(
            &std::env::var("NANO_REDIS_TLS_BOOTSTRAP_PASSWORD").unwrap(),
        ))
        .unwrap();
    assert!(
        connect(client_with_ca(parsed.as_str(), Some(&ca)).unwrap())
            .await
            .is_err(),
        "loaded ACL must supersede bootstrap default password"
    );
    let plaintext = url.replacen("rediss://", "redis://", 1);
    assert!(
        connect(client_with_ca(&plaintext, None).unwrap())
            .await
            .is_err(),
        "TLS-only server must reject plaintext"
    );
}
