set -euo pipefail

FUNC_NAME=${1:-sigmoid}
FILE_FORMAT=${2:-txt}   
NET_CONF=${3:-""}      
PORT=23233
EXEC=../bin/test_lvt_batch
CACHE_DIR=../cache

PARTY_COUNTS=(2 4 8 16)

LOGDIR="./logs"
SUMMARY_LOG="${LOGDIR}/nonlinear_100000.log"
mkdir -p "${LOGDIR}"
: > "${SUMMARY_LOG}"

if [ ! -f "${EXEC}" ]; then
    echo "Error: Executable not found at ${EXEC}"
    exit 1
fi

clear_cache() {
    local func=$1
    rm -f "${CACHE_DIR}/lvt_batch_${func}_"*
}

for N in "${PARTY_COUNTS[@]}"; do
    echo "========== Testing with ${N} parties ==========" | tee -a "${SUMMARY_LOG}"

    PROCS=()
    for (( i=1; i<=N; i++ )); do
        clear_cache "${FUNC_NAME}"

        CMD="${EXEC} ${i} ${PORT} ${N} ${FUNC_NAME} ${FILE_FORMAT}"
        [ -n "${NET_CONF}" ] && CMD+=" ${NET_CONF}"

        if [ "${i}" -eq 1 ]; then
            TMPLOG="${LOGDIR}/party1_n${N}.log"
            echo " Launching Party 1: ${CMD}" | tee -a "${SUMMARY_LOG}"
            ${CMD} > "${TMPLOG}" 2>&1 &
        else
            ${CMD} &
        fi
        PROCS+=($!)
    done

    for pid in "${PROCS[@]}"; do
        wait "${pid}"
    done
    {
        echo "----- Results for N=${N} (Party 1) -----"
        grep -E "Offline time|Online time" "${TMPLOG}"
        echo ""
    } >> "${SUMMARY_LOG}"
done

echo "ALL TESTS COMPLETE. Summary in ${SUMMARY_LOG}"
