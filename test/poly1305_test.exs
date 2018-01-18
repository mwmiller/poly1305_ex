defmodule Poly1305Test do
  use ExUnit.Case
  doctest Poly1305

  test "hmac" do
    k = "need a 32 byte shared secret key"
    m = "some short message"

    assert Poly1305.hmac(m, k) ==
             <<180, 131, 109, 239, 182, 152, 38, 175, 212, 5, 234, 60, 248, 220, 162, 85>>

    m = "some short massage"

    assert Poly1305.hmac(m, k) ==
             <<40, 203, 83, 169, 30, 211, 102, 220, 180, 219, 33, 51, 211, 153, 31, 146>>
  end

  test "aead round trip" do
    k = "need a 32 byte shared secret key"
    n = "w/ 12B nonce"
    m = "my secret message"
    a = "additional authenticated data"

    {c, t} = Poly1305.aead_encrypt(m, k, n, a)
    assert Poly1305.aead_decrypt(c, k, n, a, t) == m

    {m, a} = {"", ""}
    {c, t} = Poly1305.aead_encrypt(m, k, n, a)
    assert Poly1305.aead_decrypt(c, k, n, a, t) == m
  end

  test "aead bad data" do
    k = "need a 32 byte shared secret key"
    n = "w/ 12B nonce"
    m = "my secret message"
    a = "additional authenticated data"

    {c, t} = Poly1305.aead_encrypt(m, k, n, a)

    assert Poly1305.aead_decrypt(m, k, n, a, t) == :error
    bad_t = <<49, 54, 131, 198, 40, 6, 87, 216, 241, 210, 232, 199, 151, 159, 60, 127>>
    assert Poly1305.aead_decrypt(c, k, n, a, bad_t) == :error
    wrong_a = "extra authenticated data"
    assert Poly1305.aead_decrypt(c, k, n, wrong_a, t) == :error
    wrong_n = "w/ 12b nonce"
    assert Poly1305.aead_decrypt(c, k, wrong_n, a, t) == :error
    wrong_k = "wrong 32 bytes shared secret key"
    assert Poly1305.aead_decrypt(c, wrong_k, n, a, t) == :error
  end

  test "empty aad" do
    k = "need a 32 byte shared secret key"
    n = "w/ 12B nonce"
    m = "my secret message"

    {c, t} = Poly1305.aead_encrypt(m, k, n)
    assert Poly1305.aead_decrypt(c, k, n, t) == m
  end
end
