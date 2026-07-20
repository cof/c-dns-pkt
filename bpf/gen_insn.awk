#!/usr/bin/awk -f

# generates bpf filter from bpf-objdump disassembly

BEGIN {
    count = 0
    print "static uint64_t bpf_filter[] = {"
}

# look for lines like this
# offset: hex-codes assembler
# 10:   bf 02 00 00 00 00 00 00  mov %r2,%r0
# $1    $2 $3 $4 $5 $6 $7 $8 $9  ....
/^[ ]*[0-9a-f]+:/ {

    # extract hex bytes
    hex_str = ""
    for (i = 2; i <= 9; i++) {
        if ($i ~ /^[0-9a-f]{2}$/) {
            # append hex in reverse order to keep endian order
            hex_str = $i hex_str
        }
    }

    if (length(hex_str) != 16) { next }

    # extract assembly
    asm = ""
    for (i = 2; i <= NF; i++) {
        # first non-hex pair
        if ($i !~ /^[0-9a-f]{2}$/) {
            # gather assembly code
            for (j = i; j <= NF; j++) {
                asm = asm $j " "
            }
            break
        }
    }

    # set reloc tag if lddw
    tag = ($2 == "18") ? "<--- MAP_RELOC " : ""

    # gen asm line
    asm_line = tag asm
    sub(/ +$/, "", asm_line)
    if (asm_line != "") {
        asm_line = " " asm_line
    }

    # print hex // [index] asm
    printf "    0x%sULL, // [%02d]%s\n", hex_str, count, asm_line
    count++
}

END {
    print "};"
    print ""
}

