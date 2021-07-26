# rust-token-webapi
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

Initialization for DB (required only once)

```
USAGE:
    rust-webapi init [OPTIONS] --admin-name <admin_name> --admin-password <admin_password>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -n, --admin-name <admin_name>            SQLite database admin name
    -p, --admin-password <admin_password>    SQLite database admin password
    -d, --db-file-path <db_file_path>        SQLite database file path [default: ./users.db]
```

Run the token server

```
USAGE:
    rust-webapi run [OPTIONS] --signing-algorithm <signing_algorithm> --signing-key-path <signing_key_path>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -d, --db-file-path <db_file_path>              SQLite database file path [default: ./users.db]
    -a, --signing-algorithm <signing_algorithm>    Signing algorithm of JWT like "ES256" [default: ES256]
    -s, --signing-key-path <signing_key_path>      Signing key file path
```

## Rest APIs

Issuing token by sending your username and password via POST method.

```
http://<your_domain>:<your_port>/v1.0/tokens
```

e.g.,

```bash
$ curl -i -X POST \
  -H "Content-Type: application/json"\
  -d '{ "auth": {"username": "<name>", "password": "<password>"}}' \
  http://localhost:8000/v1.0/tokens
```

Create new user by the administrator privilege.

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
