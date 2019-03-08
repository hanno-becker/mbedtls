#!/bin/sh

CFLAGS="-m32 -g -DMBEDTLS_CONFIG_FILE='\"../configs/pdmc_config.h\"'"

echo "Cleanup..."
make clean

echo "Rebuild (flags: $CFLAGS)..."
make CFLAGS="$CFLAGS" -j > /dev/null

SRV_CMD="./programs/ssl/ssl_server2 server_addr=127.0.0.1 server_port=4433 debug_level=4 dtls=1 renegotiation=1 auth_mode=required"

VALGRIND_BASE="valgrind --tool=massif --time-unit=B --threshold=0.01 --detailed-freq=1"
CLI_CMD="./programs/ssl/ssl_client2 server_addr=127.0.0.1 server_port=4433 dtls=1"

FUNC_IGNORE=""
FUNC_IGNORE="mbedtls_ssl_setup           $FUNC_IGNORE"
FUNC_IGNORE="mbedtls_mpi_grow            $FUNC_IGNORE"
FUNC_IGNORE="mbedtls_mpi_shrink          $FUNC_IGNORE"
FUNC_IGNORE="ecp_mul_comb                $FUNC_IGNORE"
FUNC_IGNORE="mbedtls_ecp_mul_restartable $FUNC_IGNORE"
FUNC_IGNORE="ecp_normalize_jac_many      $FUNC_IGNORE"
FUNC_IGNORE="__fopen_internal            $FUNC_IGNORE"
FUNC_IGNORE="_IO_file_doallocate         $FUNC_IGNORE"
FUNC_IGNORE="strdup                      $FUNC_IGNORE"
FUNC_IGNORE="__tzstring_len              $FUNC_IGNORE"
FUNC_IGNORE="__tzfile_read               $FUNC_IGNORE"

VALGRIND_IGNORE=""
for func in $FUNC_IGNORE; do
    echo "Ignore: $func"
    VALGRIND_IGNORE="--ignore-fn=$func $VALGRIND_IGNORE"
done

VALGRIND_CMD="$VALGRIND_BASE $VALGRIND_IGNORE -- $CLI_CMD"

$SRV_CMD > /dev/null 2>&1 &
SRV_PID=$!
echo "Server started, PID $SRV_PID"

$VALGRIND_CMD > /dev/null 2>&1 &
VAL_PID=$!
echo "Valgrind started, PID $VAL_PID"

wait $VAL_PID
echo "Valgrind done, killing server"
kill $SRV_PID
echo "Done"
