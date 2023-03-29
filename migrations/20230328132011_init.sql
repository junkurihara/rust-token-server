-- Add migration script here
create table if not exists users (
  id integer primary key,
  username text not null unique,
  subscriber_id text not null unique,
  encoded_hash text not null,
  is_admin integer
);

create table if not exists client_ids (
  id integer primary key,
  client_id text not null unique
);

create table if not exists tokens (
  id integer primary key,
  subscriber_id text,
  client_id text,
  refresh_token text,
  expires integer
);
