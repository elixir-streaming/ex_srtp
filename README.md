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
* `rust` - A Rust-based backend for improved performance (requires Rust toolchain)

## Installation

The package can be installed by adding `ex_srtp` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_srtp, "~> 0.3.0"}
  ]
end
```
