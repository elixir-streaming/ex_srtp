# ExSRTP

[![Hex.pm](https://img.shields.io/hexpm/v/ex_srtp.svg)](https://hex.pm/packages/ex_srtp)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/ex_srtp/)

Elixir implementation of Secure Real-time Transport Protocol (SRTP) and
Secure Real-time Transport Control Protocol (SRTCP).

It implements the following references:
* [RFC 3711 - The Secure Real-time Transport Protocol (SRTP)](https://tools.ietf.org/html/rfc3711).
* [RFC 7714 - AES-GCM Authenticated Encryption in the Secure Real-time Transport Protocol](https://datatracker.ietf.org/doc/html/rfc7714)

## Supported Crypto Profiles

The library currently supports the following SRTP crypto profiles:
* AES_CM_128_HMAC_SHA1_80
* AES_CM_128_HMAC_SHA1_32
* AES_GCM_128

## Backends

The library supports multiple backends for cryptographic operations:
* `elixir` - Using Erlang's built-in crypto module (default)
* `rust` - A Rust-based backend for improved performance.

## Rust Backend

For the rust backend, we offer precompiled NIFs for various platforms, so if your platform is supported, you can use the rust backend without needing to compile anything. However, if your platform is not supported or you want to compile from source, you need to have the rust toolchain installed on your system. You need aslo to add `rustler` dependency and set force build config:

```elixir
{:ex_srtp, "~> 0.4.0", system_env: %{"EXSRTP_BUILD" => "1"}}
{:rustler, "~> 0.37.0"}
```

### Rust Backend and AES-GCM
The rust backend is using [graviola](https://github.com/ctz/graviola) for aes-gcm which only works on `aarch64` and `x86_64` architecture with some CPU features. If you are using an older CPU or different architecture, you should use the `elixir` backend or do not use AES_GCM crypto profile.

## Installation

The package can be installed by adding `ex_srtp` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:rustler, "~> 0.37", runtime: false} # Optional, if you want to compile the rust backend from source
    {:ex_srtp, "~> 0.4.0"}
  ]
end
```
