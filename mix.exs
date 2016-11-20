defmodule Poly1305.Mixfile do
  use Mix.Project

  def project do
    [app: :poly1305,
     version: "0.4.4",
     elixir: "~> 1.3",
     name: "Poly1305",
     source_url: "https://github.com/mwmiller/poly1305_ex",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     description: description,
     package: package,
     deps: deps]
  end

  def application do
    []
  end

  defp deps do
    [
      {:chacha20, "~> 0.3"},
      {:equivalex, "~> 0.1"},
      {:earmark, "~> 1.0", only: :dev},
      {:ex_doc, "~> 0.14", only: :dev},
    ]
  end

  defp description do
    """
    Poly1305 message authentication
    """
  end

  defp package do
    [
     files: ["lib", "mix.exs", "README*", "LICENSE*", ],
     maintainers: ["Matt Miller"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/mwmiller/poly1305_ex",
              "RFC"    => "https://tools.ietf.org/html/rfc7539",
             }
    ]
  end
end
