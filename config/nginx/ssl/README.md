# TLS certificates

Drop your certificate and private key here to serve nano over HTTPS:

```
config/nginx/ssl/
  fullchain.pem   # certificate (leaf + intermediates)
  privkey.pem     # private key
```

Both `*.pem` files are gitignored, so your key never gets committed.

Where the certs come from is up to you:

- **Let's Encrypt / certbot** — copy the issued `fullchain.pem` and `privkey.pem`
  here (e.g. from `/etc/letsencrypt/live/<domain>/`). Renew them out of band and
  re-run `docker compose ... restart nginx` to pick up the new cert.
- **Your own CA** — drop the chain + key in the same two files.
- **Self-signed** (testing / internal only — browsers will warn):

  ```sh
  ./config/nginx/generate-ssl.sh
  ```

Then enable TLS with the overlay:

```sh
docker compose -f docker-compose.opensource.yml -f docker-compose.tls.yml up -d
```

and set `BASE_URL=https://your.domain` in `.env`. See `docker-compose.tls.yml`
for the full notes.
