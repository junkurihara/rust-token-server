# rust-token-server

REST API server to handle JSON Web Token, written in Rust

## Usage

```
USAGE:
    rust-webapi [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help    Prints this message or the help of the given subcommand(s)
    init
    run
```

Before running the server, EC (P256) key pair must be prepared as:

```
# generate a keypair (actually this is a private key)
$ openssl ecparam -genkey -name prime256v1 -noout -out keyapir.pem

# extract its private key in PKCS8 format
$ openssl pkcs8 -in keypair.pem -out private_key.pem -topk8 -nocrypt

# extract its public key
$ openssl ec -in keypair.pem -pubout > public_key.pem
```

Initialization for DB (required only once)

```
USAGE:
    rust-token-server init [OPTIONS] --admin-name <admin_name> --admin-password <admin_password>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -n, --admin-name <admin_name>            SQLite database admin name
    -p, --admin-password <admin_password>    SQLite database admin password
    -c, --client-ids <client_ids>            Client ids allowed to connect the API server, split with comma like
                                             "AAAA,BBBBB,CCCC"
    -d, --db-file-path <db_file_path>        SQLite database file path [default: ./users.db]
```

Run the token server

```
USAGE:
    rust-token-server run [FLAGS] [OPTIONS] --signing-algorithm <signing_algorithm> --signing-key-path <signing_key_path>

FLAGS:
    -h, --help                Prints help information
    -o, --ignore-client-id    Ignore checking client id in token request
    -V, --version             Prints version information
    -i, --with-key-id         Include key id in JWT

OPTIONS:
    -d, --db-file-path <db_file_path>              SQLite database file path [default: ./users.db]
    -a, --signing-algorithm <signing_algorithm>    Signing algorithm of JWT like "ES256" [default: ES256]
    -s, --signing-key-path <signing_key_path>      Signing key file path
```

## Rest APIs

### Issuing (Id) token by sending your username and password via POST method

```
http://<your_domain>:<your_port>/v1.0/tokens
```

e.g.,

```bash
$ curl -i -X POST \
  -H "Content-Type: application/json"\
  -d '{ "auth": {"username": "<name>", "password": "<password>"}, "client_id": "<client_id>" }' \
  http://localhost:8000/v1.0/tokens
```

Note that the client_id is the identifier of client app.


### Create new user under the administrator privilege.

```
http://<your_domain>:<your_port>/v1.0/create_user
```

e.g.,

```bash
curl -i -X POST \
  -H "Authorization: Bearer <admin's jwt>" \
  -H "Content-Type: application/json" \
  -d '{ "auth": {"username": "<new_user_name>", "password": "<new_user_password>"}}' \
  http://localhost:8000/v1.0/create_user
```
