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
    a+s |> :binary.encode_unsigned(:little) |> result_pad |> binary_part(0,16)
  end

  def key_gen(k,n), do: Chacha20.block(k,n,0) |> binary_part(0,32)

  defp result_pad(s) when byte_size(s) >= 16, do: s
  defp result_pad(s) when byte_size(s) < 16, do: result_pad(s<><<0>>)

  defp process_message(<<>>,_r,a), do: a
  defp process_message(m,r,a) do
    size = byte_size m
    bend = Enum.min([16,size])
    rest = size - bend
    n = binary_part(m,0,bend)<><<1>> |> :binary.decode_unsigned(:little)
    binary_part(m,bend,rest) |> process_message(r,rem((r * (a + n)) , p))
  end

end
