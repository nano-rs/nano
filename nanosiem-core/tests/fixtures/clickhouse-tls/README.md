Local TLS test fixtures only. The server key is deliberately public test material,
trusted only by this fixture CA; never install or use it outside these tests.
`server.der` is valid for DNS `localhost`, deliberately not the IP `127.0.0.1`.
The unrelated CA supports the wrong-root negative. Certificates expire in 2036.
No production credentials, customer certificates, external server or SQL engine
are used by the transport tests.
