# ExSRTP

[![Hex.pm](https://img.shields.io/hexpm/v/ex_srtp.svg)](https://hex.pm/packages/ex_srtp)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/ex_srtp/)

Elixir implementation of Secure Real-time Transport Protocol (SRTP) and
Secure Real-time Transport Control Protocol (SRTCP).

It implements the following references:
* [RFC 3711 - The Secure Real-time Transport Protocol (SRTP)](https://tools.ietf.org/html/rfc3711).

## Backends

The library supports multiple backends for cryptographic operations:
* `elixir` - Using Erlang's built-in crypto module (default)
* `rust` - A Rust-based backend for improved performance.

## Rust Backend

For the rust backend, we offer precompiled NIFs for various platforms, so if your platform is supported, you can use the rust backend without needing to compile anything. However, if your platform is not supported or you want to compile from source, you need to have the rust toolchain installed on your system. You need aslo to add `rustler` dependency and set force build config:

```elixir
{:rustler, "~> 0.37.0"}
```

```elixir
config :rust_precompiled, :force_build, ex_srtp: true
```

## Installation

The package can be installed by adding `ex_srtp` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:rustler, "~> 0.37", runtime: false} # Optional, if you want to compile the rust backend from source
    {:ex_srtp, "~> 0.3.0"}
  ]
end
```
