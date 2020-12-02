rule xor_loop : xoring {
    meta:
      description = "Find XOR encrypted string using the `xor` loop"
      author      = "cedric"
      version     = "0.1"
    condition:
        uint32be(0) == 0x7F454C46 and
        for any l in (0..filesize):(
            for any n in (0x00..0xff):(
                uint8(l)     ^ 0x69  == 0x70 and
                uint8(l + 1) ^ 0x69  == 0x77 and
                uint8(l + 2) ^ 0x69  == 0x6e and
                uint8(l + 3) ^ 0x69  == 0x65 and
                uint8(l + 4) ^ 0x69  == 0x64 and
                uint8(l + 5) ^ 0x69  == 0x63 and
                uint8(l + 6) ^ 0x69  == 0x72 and
                uint8(l + 7) ^ 0x69  == 0x32 and
                uint8(l + 8) ^ 0x69  == 0x30 and
                uint8(l + 9) ^ 0x69  == 0x32 and
                uint8(l + 10)^ 0x69  == 0x30
            )
        )
}
