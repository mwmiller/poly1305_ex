defmodule Poly1305Test do
  use PowerAssert
  doctest Poly1305

  test "hmac" do
    k = "need a 64-byte key which breaks down into r and s to do the hmac"
    m = "some short message"

    assert Poly1305.hmac(m,k) == <<186, 21, 153, 88, 157, 16, 187, 65, 47, 135, 16, 191, 154, 105, 127, 18>>

    m = "some short massage"
    assert Poly1305.hmac(m,k) == <<193, 127, 235, 46, 77, 88, 115, 45, 208, 122, 147, 75, 16, 132, 134, 101>>
  end

  test "aead round trip" do
    k   = "need a 32 byte shared secret key"
    n   = "w/ 12B nonce"
    m   = "my secret message"
    a   = "additional authenticated data"

    {c,t} = Poly1305.aead_encrypt(m,k,n,a)
    assert Poly1305.aead_decrypt(c,k,n,a,t) == m

    {m,a} = {"",""}
    {c,t} = Poly1305.aead_encrypt(m,k,n,a)
    assert Poly1305.aead_decrypt(c,k,n,a,t) == m

  end

  test "aead bad data" do
    k   = "need a 32 byte shared secret key"
    n   = "w/ 12B nonce"
    m   = "my secret message"
    a   = "additional authenticated data"

    {c,t} = Poly1305.aead_encrypt(m,k,n,a)

    assert Poly1305.aead_decrypt(m,k,n,a,t)     == :error
    bad_t = <<49, 54, 131, 198, 40, 6, 87, 216, 241, 210, 232, 199, 151, 159, 60, 127>>
    assert Poly1305.aead_decrypt(c,k,n,a,bad_t) == :error
    wrong_a   = "extra authenticated data"
    assert Poly1305.aead_decrypt(c,k,n,wrong_a,t) == :error
    wrong_n   = "w/ 12b nonce"
    assert Poly1305.aead_decrypt(c,k,wrong_n,a,t) == :error
    wrong_k   = "wrong 32 bytes shared secret key"
    assert Poly1305.aead_decrypt(c,wrong_k,n,a,t) == :error

  end

end
