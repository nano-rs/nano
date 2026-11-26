# TLS certificates

Put your certificate and private key here to serve nano over HTTPS:

```
config/nginx/ssl/
  fullchain.pem   # certificate (leaf + intermediates)
  privkey.pem     # private key
```

Both `*.pem` files are gitignored, so your key never gets committed.

Where the certificate comes from is up to you:

- **Let's Encrypt (certbot):** copy the issued `fullchain.pem` and
  `privkey.pem` here, for example from `/etc/letsencrypt/live/<domain>/`.
- **Your own CA:** put the chain and key in the same two files.
- **Self-signed** (testing only; browsers will warn). This makes a
  certificate for `localhost`:

  ```sh
  ./config/nginx/generate-ssl.sh
  ```

Then run the installer again from the install directory with your HTTPS
address and the TLS file:

```sh
NANO_BASE_URL=https://nano.example.com NANO_COMPOSE_OVERLAYS=docker-compose.tls.yml ./install.sh
```

The installer checks the certificate, saves both settings in `.env` (so later
restarts and upgrades keep HTTPS), sets `NANOSIEM_DEV_MODE=false` so login
cookies are marked `Secure`, and restarts the stack.

To renew, replace the two files and restart nginx:

```sh
docker compose -f docker-compose.opensource.yml -f docker-compose.tls.yml restart nginx
```

See `docker-compose.tls.yml` for the full notes.
