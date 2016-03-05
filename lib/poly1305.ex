defmodule Poly1305 do
  require Chacha20
  import Bitwise

  @moduledoc """
  Poly1305 message authentication

  https://tools.ietf.org/html/rfc7539
  """
  @typedoc """
  Encryption key
  """
  @type key :: <<_::32 * 8>>
  @typedoc """
  Per-message nonce

  By convention, the first 4 bytes should be sender-specific.
  The trailing 8 bytes may be as simple as a counter.
  """
  @type nonce :: <<_::12 * 8 >>
  @typedoc """
  MAC tag
  """
  @type tag :: <<_::16 * 8 >>

  defp clamp(r), do: r &&& 0x0ffffffc0ffffffc0ffffffc0fffffff

  defp split_key(k), do: {binary_part(k,0,16)  |> :binary.decode_unsigned(:little) |> clamp,
                         binary_part(k,16,16) |> :binary.decode_unsigned(:little)}

  defp p, do: 0x3fffffffffffffffffffffffffffffffb

  @doc """
  Compute a Message authentication code

  The one-time key should never be reused.
  """
  @spec hmac(binary,key) :: tag
  def hmac(m,k) do
    {r,s} = split_key(k)
    process_message(m,r,0)+s |> :binary.encode_unsigned(:little) |> result_align
  end

  @doc false
  def key_gen(k,n), do: Chacha20.block(k,n,0) |> binary_part(0,32)

  defp result_align(s) when byte_size(s) >= 16, do: binary_part(s,0,16)
  defp result_align(s) when byte_size(s) < 16, do: align_pad(s,16)

  defp process_message(<<>>,_r,a), do: a
  defp process_message(m,r,a) do
    size = byte_size m
    bend = Enum.min([16,size])
    rest = size - bend
    n = binary_part(m,0,bend)<><<1>> |> :binary.decode_unsigned(:little)
    binary_part(m,bend,rest) |> process_message(r,rem((r * (a + n)) , p))
  end
  @doc """
    authenticated encryption with additional data - encryption

    - message to be encrypted
    - shared secret key
    - one-time use nonce
    - additional authenticated data

    The return value will be a tuple of `{ciphertext, MAC}`

    The algorithm is applied as described in RFC7539:

    - The key and nonce are used to encrypt the message with ChaCha20.
    - The one-time MAC key is derived from the cipher key and nonce.
    - The ciphertext and additional data are authenticated with the MAC
  """
  @spec aead_encrypt(binary,key,nonce,binary) :: {binary, tag}
  def aead_encrypt(m,k,n,a) do
      otk = key_gen(k,n)
      c   = Chacha20.crypt(m,k,n,1)
      md  = align_pad(a,16)<>align_pad(c,16)<>msg_length(a)<>msg_length(c)

      {c, hmac(md,otk)}
  end

  @doc """
    authenticated encryption with additional data - decryption

    - encrypted message
    - shared secret key
    - one-time use nonce
    - additional authenticated data
    - MAC

    On success, returns the plaintext message.  If the message cannot be
    authenticated `:error` is returned.
  """
  @spec aead_decrypt(binary,key,nonce,binary,tag) :: binary | :error
  def aead_decrypt(c,k,n,a,t) do
      otk = key_gen(k,n)
      md  = align_pad(a,16)<>align_pad(c,16)<>msg_length(a)<>msg_length(c)
      m   = Chacha20.crypt(c,k,n,1)
      if hmac(md,otk) == t, do: m, else: :error
  end

  defp msg_length(s), do: s |> byte_size |> :binary.encode_unsigned(:little) |> align_pad(8)

  defp align_pad(<<>>,_n), do: <<>>   # Let empties stay empty, will affect message padding, not result padding.
  defp align_pad(s,n), do: s<>zeroes(n - rem(byte_size(s), n))

  defp zeroes(n), do: zero_loop(<<>>, n)
  defp zero_loop(z,0), do: z
  defp zero_loop(z,n), do: zero_loop(z<><<0>>, n-1)

end
