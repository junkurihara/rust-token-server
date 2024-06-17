# rust-token-server

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Unit Test](https://github.com/junkurihara/rust-token-server/actions/workflows/ci.yml/badge.svg)
![Build and Publish Docker](https://github.com/junkurihara/rust-token-server/actions/workflows/docker_build_push.yml/badge.svg)
![ShiftLeft Scan](https://github.com/junkurihara/rust-token-server/actions/workflows/shiftleft-analysis.yml/badge.svg)
[![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/jqtype/id-token-server)](https://hub.docker.com/r/jqtype/id-token-server)


REST API server to handle JSON Web Token, written in Rust

## Installation and build

Execute the following command at the root of the cloned directory.

```bash:
% cargo build --package rust-token-server --release
```

Now you get the executable file `./target/release/rust-token-server`.

## Usage

```bash:
% ./rust-token-server -h
Authentication server handling id token in the context of OIDC

Usage: rust-token-server [COMMAND]

Commands:
  run    Run the authentication and token server
  admin  Admin command to update admin password
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Preparing signing keys

Before running the server, ECDSA (P256) key pair or EdDSA (Ed25519) must be prepared as:

- P256

    ```bash:
    # generate a keypair (actually this is a private key)
    % openssl ecparam -genkey -name prime256v1 -noout -out keypair.pem

    # extract its private key in PKCS8 format
    % openssl pkcs8 -in keypair.pem -out private_key.pem -topk8 -nocrypt

    # extract its public key
    % openssl ec -in keypair.pem -pubout > public_key.pem
    ```

- Ed25519

    ```bash:
    # generate ed25519 private key
    % openssl genpkey -algorithm ed25519 -out private_key.pem

    # extract its public key
    % openssl pkey -in privatekey.pem -pubout > public_key.pem
    ```

### Run the authentication server

```bash:
% ./rust-token-server run -h
Run the authentication and token server

Usage: rust-token-server run [OPTIONS] --token-issuer <URL> --signing-key-path <PATH>

Options:
  -l, --listen-address <ADDRESS>       Listen address [default: 127.0.0.1]
  -p, --port <PORT>                    Listen port [default: 3000]
  -t, --token-issuer <URL>             Issuer of Id token specified as URL like "https://example.com/issue"
  -c, --client-ids <IDs>               Client ids allowed to connect the API server, split with comma like 'AAAA,BBBBB,CCCC'. If not specified, any client can be connected.
  -s, --signing-key-path <PATH>        Signing key file path
  -d, --db-file-path <PATH>            SQLite database file path [default: ./users.db]
  -h, --help                           Print help
```

Note that client ID's are optional, but it is recommended to specify some ID strings since they are treated as "Application IDs" allowed to connect the server.

At the first time, the server automatically generate the sqlite database to store the user authentication data and refresh tokens. Then, **the administrator user "`admin`" is created. The password of `admin` is set by an environment variable `ADMIN_PASSWORD`. If `ADMIN_PASSWORD` is not set, it is randomly generated and shown in the log.

We should note that the name of `admin` cannot be changed. But its password can be updated by `./rust-token-server admin` command or a REST API.

### Update admin password via CLI

You can update admin password as follows even if the server is running.

```bash:
% rust-token-server admin --help
Admin command to update admin password

Usage: rust-token-server admin [OPTIONS] --admin-password <PASSWORD>

Options:
  -p, --admin-password <PASSWORD>  SQLite database admin password
  -d, --db-file-path <PATH>        SQLite database file path [default: ./users.db]
  -h, --help                       Print help
```

## Rest APIs

### Issue ID token by sending your username and password via POST method

This can be viewed as 'login' API, and you can get ID token and some meta data via the API.

```url:
http://<your_domain>:<your_port>/v1.0/tokens
```

For example, you can call it as:

```bash
% curl -i -X POST \
  -H "Content-Type: application/json"\
  -d '{ "auth": {"username": "<name>", "password": "<password>"}, "client_id": "<client_id>" }' \
  http://localhost:8000/v1.0/tokens
```

Note that the client_id is the identifier of client app and it is optional.

### Create new user under the administrator privilege

```url:
http://<your_domain>:<your_port>/v1.0/create_user
```

For example, you can call it as:

```bash
% curl -i -X POST \
  -H "Authorization: Bearer <admin's jwt>" \
  -H "Content-Type: application/json" \
  -d '{ "auth": {"username": "<new_user_name>", "password": "<new_user_password>"}}' \
  http://localhost:8000/v1.0/create_user
```

### Delete an existing user under the administrator privilege

```url:
http://<your_domain>:<your_port>/v1.0/delete_user
```

For example, you can call it as:

```bash
% curl -i -X POST \
  -H "Authorization: Bearer <admin's jwt>" \
  -H "Content-Type: application/json" \
  -d '{ "username": "<target_user_name>"}' \
  http://localhost:8000/v1.0/delete_user
```

### List users under the administrator privilege

```url:
http://<your_domain>:<your_port>/v1.0/list_users
```

For example, you can call it as:

```bash
% curl -i -X POST \
  -H "Authorization: Bearer <admin's jwt>" \
  -H "Content-Type: application/json" \
  -d '{ "page": 1 }' \
  http://localhost:8000/v1.0/list_users
```

The `page` can be omitted. If it is omitted, the first page is shown. Note that `page` must start from 1. The response message includes the total number of pages, and at most 20 users are shown in a page. In the response message, `username`, `subscriber_id` and `is_admin` are contained for each user.

### Update username and password

Users can update their own password and username. But note that `admin` can update only its password, the username `admin` cannot be changed.

```url:
http://<your_domain>:<your_port>/v1.0/update_user
```

For example, you can call it as:

```bash:
% curl -i -X POST \
  -H "Authorization: Bearer <user's jwt>" \
  -H "Content-Type: application/json" \
  -d '{ "auth": {"username": ""<new_user_name>"", "password": "<new_user_password>"}}' \
  http://localhost:8000/v1.0/update_user
```

### JWKs to retrieve the public key by clients

This is called by clients when ID tokens are verified.

```url:
http://<your_domain>:<your_port>/v1.0/jwks
```

### Refresh ID tokens

ID tokens can be refreshed by sending refresh token.

```bash:
http://<your_domain>:<your_port>/v1.0/refresh
```

For example, you can call it as:

```bash:
% curl -i -X POST \
  -H "Content-Type: application/json" \
  -d '{ "refresh_token": "<refresh_token>", "client_id": "<client_id>" }'
  http://localhost:8000/v1.0/refresh
```

Where the `client_id` is still optional.

---

## RSA blind signatures

This server dynamically generates RSA key pairs for RSA blind signatures. The key pairs are generated when the server is started, and periodically rotated every 24 hours. The key pairs are stored in the memory and not saved in the file system.

### Getting a public key for RSA blind signatures

This simply exposes RSA public key(s) for RSA blind signatures in JWKs format.

```bash
http://<your_domain>:<your_port>/v1.0/blindjwks
```

### Signing a message blinded by the user

```bash
http://<your_domain>:<your_port>/v1.0/blindsign
```

For example, you can call it as:

```bash:
% curl -i -X POST \
  -H "Authorization: Bearer <user's jwt>" \
  -H "Content-Type: application/json" \
  -d '{ "blinded_token": "<blinded_token>" }'
  http://localhost:8000/v1.0/blindsign
```

where the `blinded_token` is defined in JSON format as follows:

```json
{
  "blinded_token_message": "<raw rsa blinded message>",
  "blinded_token_options":{
    "hash": "<hash algorithm like: Sha384>",
    "deterministic": <boolean>,
    "salt_len": <integer>
  }
}
