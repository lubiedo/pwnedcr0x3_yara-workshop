rule xor_modifier : xoring {
    meta:
      description = "Find XOR encrypted string using the `xor` modifier"
      author      = "cedric"
      version     = "0.1"
    strings:
        $s = "pwnedcr2020" xor
    condition:
        uint32be(0) == 0x7F454C46 and $s
}
