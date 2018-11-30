#!/bin/sh

BUILD_DIR="./library"

LIBFILES="libmbedcrypto.a libmbedtls.a libmbedx509.a"

SUMMARY_ONLY=0
LIMIT=25
info="No additional information provided"

print_usage() {
    echo "\nExtract static memory usage statistics for an Mbed TLS build.\n"
    echo "Usage: $0 [options]"
    echo "  -i|--info\tAdditional information to log, such as toolchain and compilation flags."
    echo "  -s|--summary\tPrint only the summary."
    echo "  -l|--limit num\tPrint only the largest 'num' symbols of the given type. (Default: $LIMIT) "
    echo "  -h|--help\tPrint this help."
    echo "  -d|--dir=BUILD_DIR\tThe build directory containing the 'library' folder (default: ${BUILD_DIR})"
}

get_options() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -d|--dir)
                shift; BUILD_DIR=$1
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            -s|--summary)
                SUMMARY_ONLY=1
                ;;
            -l|--limit)
                shift; LIMIT=$1
                ;;
            -i|--info)
                shift; info=$1
                ;;
            *)
                echo "Unknown argument: $1"
                print_usage
                exit 1
                ;;
        esac
        shift
    done
}

get_options "$@"

commit=$( git show | head -n 1 | awk '{print $2}' )
date=$( git show --date=short | grep "Date" | awk '{print $2}' )
tag=$( git describe --exact-match HEAD ) 2>/dev/null

# Print some metadata about the build

echo "! COMMIT $commit"
echo "! DATE $date"
echo "! INFO $info"
echo "! TAG $tag"

echo ""

report_syms() {
    echo "! $2 $1"
    nm --line-numbers --radix=d --size-sort --reverse $1 | grep " [$3] " | sort --reverse | head -n $LIMIT | awk '{ printf( "%6d %s %s\n", $1, $3, $4 ); }'
    echo "! END\n"
}

# Report static memory usage (RAM and ROM)
for lib in $LIBFILES; do
    lib_full="$BUILD_DIR/$lib"
    echo "! SUMMARY $BUILD_DIR/$lib"
    size --format=sysv --radix=10 $lib_full | ./convert_size_out.awk
    echo "! END\n"
done

SYMTYPES="CODE-tT DATA-dD RODATA-rR BSS-bB"
if [ $SUMMARY_ONLY -eq 0 ]; then
    for symtype in $SYMTYPES; do
        type=${symtype%*-*}
        specifier=${symtype#*-*}
        for lib in $LIBFILES; do
            report_syms "$BUILD_DIR/$lib" $type $specifier
        done
    done
fi
