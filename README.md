# HCAuth

A Rust library for interacting with the Hack Club OAuth and Identity API.

It supports OAuth login, token exchange, identity fetching, external verification checks, and JWT (`id_token`) verification using Hack Club JWKs.

---

## Setup

Create a `hca.toml` file:

```toml
client_id = "your_client_id"
client_secrets = "your_client_secret"
redirect_uri = "http://localhost:3000/callback"
```

Then you can start sniffing users and log them into your application :3.
