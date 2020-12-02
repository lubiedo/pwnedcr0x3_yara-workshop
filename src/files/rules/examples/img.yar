rule images : my_tools search_tool {
    meta:
        description = "Get all JPEG and PNG images, avoiding EXIF metadata"
        author      = "cedric"
        version     = "0.1"
    strings:
        $jpg = { FF D8 FF (DB|E0|EE|E1) }
        $str = "Exif" nocase
    condition:
        ( $jpg and not $str ) or uint32be(0) == 0x89504E47 /* png */
}
