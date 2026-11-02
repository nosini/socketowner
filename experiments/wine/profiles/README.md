# Wine layout profiles

A profile is a trusted description of one exact amd64 Wine server ELF file.
Its hash is checked against the **running executable**, not a version string or
same-named pathname. The observer refuses other binaries.

`wineserver-3bb468ca4d60c890.json` is the verified VM test build. Its Wine socket
source matches DW Wine `b75a4125963073b01d2b3bfce6060d697d02066b`; the build also
contains local display-only patches through
`a451b29d1ca0baf2da86d3cdf0b9bffdc9752226`. It is not a profile for the official
download's possibly different compiler/linker/strip output. Offsets and the
`current` symbol came from that exact ELF's DWARF and symbol table.

Use `-make-profile` with matching symbols/DWARF for another trusted build and
review the result. The current generator does not consume separate debug files
or infer layouts from a stripped binary. Do not edit the hash to make a
different runner pass: layout and symbol location must be established for that
binary. Normal Wine/Proton updates may require another profile, but do not
require patching or rebuilding Wine to add annotations.
