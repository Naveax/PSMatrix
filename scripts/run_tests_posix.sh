#!/usr/bin/env bash
set -uo pipefail

TIMEOUT_SECONDS=240
SKIP_OCI=0
while (($#)); do
    case "$1" in
        --timeout)
            shift
            TIMEOUT_SECONDS="${1:?--timeout requires seconds}"
            ;;
        --skip-oci)
            SKIP_OCI=1
            ;;
        *)
            printf 'Unknown argument: %s\n' "$1" >&2
            exit 2
            ;;
    esac
    shift
done

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
PYTHON_BIN="${PSMATRIX_TEST_PYTHON:-$(command -v python3)}"
SOURCE="$ROOT/src"
OCI_TESTS=(
    test_image_reference_validation
    test_install_pins_digest_and_probes_exact_version
    test_mutable_local_tag_requires_explicit_trust
    test_version_mismatch_is_rejected
    test_cli_executes_registered_oci_runtime
)

TOTAL="$({ grep -h -E '^[[:space:]]+def test_' "$ROOT"/tests/test_*.py || true; } | wc -l | tr -d ' ')"
EXPECTED="$TOTAL"
if ((SKIP_OCI)); then
    EXPECTED=$((TOTAL - ${#OCI_TESTS[@]}))
fi
PASSED=0

run_case() {
    local label="$1"
    shift
    local isolated log rc
    isolated="$(mktemp -d -t psmatrix-test-env-XXXXXXXX)"
    chmod 0755 "$isolated"
    mkdir -m 1777 "$isolated/tmp"
    mkdir -m 0755 "$isolated/cache" "$isolated/config" "$isolated/data"
    log="$isolated/test.log"

    printf '== %s ==\n' "$label"
    (
        cd "$ROOT"
        export PYTHONPATH="$SOURCE${PYTHONPATH:+:$PYTHONPATH}"
        export TERM="${TERM:-dumb}"
        export HOME="$isolated"
        export TMPDIR="$isolated/tmp"
        export TMP="$isolated/tmp"
        export TEMP="$isolated/tmp"
        export XDG_CACHE_HOME="$isolated/cache"
        export XDG_CONFIG_HOME="$isolated/config"
        export XDG_DATA_HOME="$isolated/data"
        export PSMATRIX_HOME="$isolated/psmatrix-home"
        export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1 PYTHONNOUSERSITE=1
        exec /usr/bin/timeout --signal=TERM --kill-after=5s "${TIMEOUT_SECONDS}s" "$@"
    ) >"$log" 2>&1
    rc=$?
    cat "$log"
    rm -rf -- "$isolated"

    if ((rc == 124 || rc == 137)); then
        printf 'Test command timed out after %ss: %s\n' "$TIMEOUT_SECONDS" "$label" >&2
        exit 124
    fi
    if ((rc != 0)); then
        exit "$rc"
    fi
}

if ((!SKIP_OCI)); then
    for name in "${OCI_TESTS[@]}"; do
        run_case "tests.test_oci.OciRuntimeTests.$name" \
            "$PYTHON_BIN" -m unittest "tests.test_oci.OciRuntimeTests.$name" -v
        PASSED=$((PASSED + 1))
    done
fi

while IFS= read -r path; do
    [[ "$(basename -- "$path")" == "test_oci.py" ]] && continue
    stem="$(basename -- "$path" .py)"
    module="tests.$stem"
    count="$({ grep -E '^[[:space:]]+def test_' "$path" || true; } | wc -l | tr -d ' ')"
    run_case "$module" "$PYTHON_BIN" -m unittest "$module" -v
    PASSED=$((PASSED + count))
done < <(find "$ROOT/tests" -maxdepth 1 -type f -name 'test_*.py' -print | sort)

if ((PASSED != EXPECTED)); then
    printf 'Test accounting mismatch: expected %d, passed %d\n' "$EXPECTED" "$PASSED" >&2
    exit 2
fi
printf 'PSMatrix tests: %d/%d PASS\n' "$PASSED" "$EXPECTED"
