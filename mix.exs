defmodule ExSRTP.MixProject do
  use Mix.Project

  @version "0.2.0"
  @github_url "https://github.com/elixir-streaming/ex_srtp"

  def project do
    [
      app: :ex_srtp,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "SRTP (Secure Real-time Transport Protocol) implementation in Elixir",
      package: package(),
      name: "ExSRTP",
      source_url: @github_url,
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:ex_rtp, "~> 0.4.0"},
      {:ex_rtcp, "~> 0.4.0"},
      {:ex_doc, "~> 0.30", only: :dev, runtime: false}
    ]
  end

  def package do
    [
      maintainers: ["Billal Ghilas"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => @github_url
      }
    ]
  end

  def docs do
    [
      main: "readme",
      extras: ["README.md", "LICENSE"],
      formatters: ["html"],
      source_ref: "v#{@version}"
    ]
  end
end
