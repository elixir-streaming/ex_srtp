defmodule ExSRTP.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_srtp,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps()
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
end
