import "pe"
rule silent_banker : banker
{
    // c++ comment
    /* c style comment */
    meta:
        description  = "This is just an example"
        threat_level = 3
        in_the_wild  = true
        hash1        = "fc5e038d38a57032085441e7fe7010b0"
    strings:
        $a   = {6A 40 68 00 30 00 [01-04] 6A 14 8D 91}
        $b   = {8D 4D B0 2B C1 ?? C? 27 99 6A 4E 59 F7 F9}
        $c01 = "ABC" fullword wide
        $c02 = /DEF/ ascii nocase
    condition:
        pe.characteristics & pe.EXECUTABLE_IMAGE and uint16be(0) == 0x4d5a and (
          $a or $b or any of ($c*)
        )
}
