/**
 * Some of the rules created *during* the workshop.
 */
import "elf"
rule passwd_file : system_tools {
  meta:
    description = "Recognizes passwd files"
    author      = "cedric"
    date        = "05-12-2020"
  strings:
    $str00      = "root" fullword
    $str01      = "guest" fullword
    $str02      = ":x:"
    $str03      = "bin/"

  condition:
    any of ($str00,$str01) and all of ($str02,$str03)
}

rule dummy_malware {
  strings:
    $s0   = "this is some malicious data! w00t w00t!"
    $s1   = "death to COVID-19"
  condition:
    uint32be(0) == 0x7f454c46 and filesize < 25KB and all of them
}

rule dummy_malware_with_ELF_module {
  strings:
    $s0   = "this is some malicious data! w00t w00t!"
    $s1   = "death to COVID-19"
  condition:
    elf.type == elf.ET_DYN and filesize < 25KB and all of them
}

rule dummy_malware_with_ELF_module_section {
  condition:
    elf.type == elf.ET_DYN and filesize < 25KB and 
      for any n in (0..elf.number_of_sections):(
        elf.sections[n].name == ".evil_section"
      )
}

rule dummy_malware_in_mem {
  strings:
    $s0   = "this is some malicious data! w00t w00t!"
    $s1   = "death to COVID-19"
  condition:
     any of them
}
