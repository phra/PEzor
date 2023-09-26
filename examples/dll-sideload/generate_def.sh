#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: $0 <OriginalDLL.dll>"
    exit 1
fi

original_dll="$1"
source_dll="ForwardedDLL.c"
output_def="ForwardedDLL.def"
output_dll="ForwardedDLL.dll"

winedump dump -C -j export "$original_dll" | \
awk '
    BEGIN {
        print "EXPORTS"
    }
    /Entry/,/Done/ {
        if ($2 ~ /^[0-9]+/) {
            ordinal = $2
            name = $3
            if (name ~ /</) { 
                # Exported by ordinal (TODO: syntax error in .def file)
                # printf "    @%s=%s.#%s @%s\n", ordinal, "library", ordinal, ordinal
            } else if (name !~ /DllMain/){
                # Exported function with a name
                printf "    %s=%s.%s @%s\n", name, "library", name, ordinal
            }
        }                            
    }
' > $output_def

# Compile the C++ source code into a DLL using clang and mingw
x86_64-w64-mingw32-gcc -shared -o "$output_dll" "$source_dll" "$output_def"

echo "Forwarded DLL created: $output_dll"
