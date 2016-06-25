defmodule KeygenTest do
  use ExUnit.Case
  import VectorHelper
  doctest Poly1305

  test "rfc example" do
    k   = from_hex """
                    80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f
                    90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f
                   """
    n   = from_hex "00 00 00 00 00 01 02 03 04 05 06 07"
    otk = from_hex """
                    8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71
                    a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46
                   """

    assert Poly1305.key_gen(k,n) == otk
  end

  test "test vector #1" do
    k   = from_hex """
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                   """
    n   = from_hex "00 00 00 00 00 00 00 00 00 00 00 00"
    otk = from_hex """
                    76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
                    bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
                   """

    assert Poly1305.key_gen(k,n) == otk
  end

  test "test vector #2" do
    k   = from_hex """
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
                   """
    n   = from_hex "00 00 00 00 00 00 00 00 00 00 00 02"
    otk = from_hex """
                    ec fa 25 4f 84 5f 64 74 73 d3 cb 14 0d a9 e8 76
                    06 cb 33 06 6c 44 7b 87 bc 26 66 dd e3 fb b7 39
                   """

    assert Poly1305.key_gen(k,n) == otk
  end

  test "test vector #3" do
    k   = from_hex """
                    1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
                    47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
                   """
    n   = from_hex "00 00 00 00 00 00 00 00 00 00 00 02"
    otk = from_hex """
                    96 5e 3b c6 f9 ec 7e d9 56 08 08 f4 d2 29 f9 4b
                    13 7f f2 75 ca 9b 3f cb dd 59 de aa d2 33 10 ae
                   """

    assert Poly1305.key_gen(k,n) == otk
  end

end
