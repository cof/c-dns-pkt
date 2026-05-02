#!/usr/bin/awk -f

# generates bpf filter from  bpf-objdump output

BEGIN {
    count = 0
    print "static uint64_t bpf_filter[] = {"
}

# look for likes like 10:   bf 02 00 00 00 00 00 00  mov %r2,%r0
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
        if ($i !~ /^[0-9a-f]{2}$/) {
            for (j = i; j <= NF; j++) {
                asm = asm $j " "
            }
            break
        }
    }

    # set reloc tag
    tag = ($2 == "18") ? " <--- MAP_RELOC " : ""
    # print hex // [index] [reloc] asm
    printf "    0x%sULL, // [%02d]%s%s\n", hex_str, count, tag, asm
    count++
}

END {
    print "};"
    print ""
}

