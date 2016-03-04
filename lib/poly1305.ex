defmodule Poly1305 do
  require Chacha20
  import Bitwise

  def clamp(r), do: r &&& 0x0ffffffc0ffffffc0ffffffc0fffffff

  def split_key(k), do: {binary_part(k,0,16)  |> :binary.decode_unsigned(:little) |> clamp,
                         binary_part(k,16,16) |> :binary.decode_unsigned(:little)}

  def p, do: 0x3fffffffffffffffffffffffffffffffb

  def hmac(m,k) do
    {r,s} = split_key(k)
    a = process_message(m, r,0)
    a+s |> :binary.encode_unsigned(:little) |> result_align
  end

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

  def aead_encrypt(m,k,n,a) do
      otk = key_gen(k,n)
      {c,_s} = Chacha20.crypt_bytes(m,{k,n,1,""},[])
      md  = align_pad(a,16)<>align_pad(c,16)<>msg_length(a)<>msg_length(c)

      {c, hmac(md,otk)}
  end

  def aead_decrypt(c,k,n,a,t) do
      otk = key_gen(k,n)
      md  = align_pad(a,16)<>align_pad(c,16)<>msg_length(a)<>msg_length(c)
      case hmac(md,otk) do
          ^t -> {m, _} = Chacha20.crypt_bytes(c,{k,n,1,""},[])
                m
          _  -> :error # Unauthenticated message.
      end
  end

  def msg_length(s), do: s |> byte_size |> :binary.encode_unsigned(:little) |> align_pad(8)

  def align_pad(s,n), do: s<>zeroes(n - rem(byte_size(s), n))

  defp zeroes(n), do: zero_loop(<<>>, n)
  defp zero_loop(z,0), do: z
  defp zero_loop(z,n), do: zero_loop(z<><<0>>, n-1)

end
