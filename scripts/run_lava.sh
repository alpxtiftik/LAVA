#!/bin/bash
# LAVA (Local AI Vulnerability Auditor) pipeline runner (Linux)

# Parse arguments.  _MODULES_FLAG is a fresh name (never inherited from the
# environment) so a stray $MODULES in the caller's env cannot shadow it.
_MODULES_FLAG=""
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -LogDir|--log-dir) LOGDIR="$2"; shift ;;
        -OutDir|--out-dir) BASEOUTDIR="$2"; shift ;;
        -Modules|--modules) _MODULES_FLAG="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 2 ;;
    esac
    shift
done

if [ -z "$LOGDIR" ]; then
    echo "Error: -LogDir is required."
    exit 2
fi

# Validate an explicitly-passed --modules before doing any work (the
# config-derived default is resolved later, after ai_config.env is read).
if [ -n "$_MODULES_FLAG" ]; then
    case ",$_MODULES_FLAG," in
        *,credentials,*|*,cve,*) ;;
        *) echo "Error: --modules must include 'credentials' and/or 'cve' (got: '$_MODULES_FLAG')."; exit 2 ;;
    esac
fi

# The pipeline runs `python3 src/core/...` and reads `config/...` as relative
# paths, so it MUST run from the repo root. Make the user's paths absolute
# first (they were relative to the caller's cwd), then cd to the root.
_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
_LAVA_ROOT="$(dirname "$(dirname "$_SCRIPT")")"
case "$LOGDIR" in
    /*) ;;
    *)  LOGDIR="$(cd "$LOGDIR" 2>/dev/null && pwd)" || LOGDIR="$PWD/$LOGDIR" ;;
esac
if [ -n "${BASEOUTDIR:-}" ]; then
    case "$BASEOUTDIR" in /*) ;; *) BASEOUTDIR="$PWD/$BASEOUTDIR" ;; esac
fi
cd "$_LAVA_ROOT" || { echo "Error: cannot enter the LAVA root ($_LAVA_ROOT)."; exit 1; }

# config/ai_config.env is gitignored; seed it from the template on first run.
if [ ! -f "config/ai_config.env" ] && [ -f "config/ai_config.example.env" ]; then
    cp config/ai_config.example.env config/ai_config.env
    echo "[*] Created config/ai_config.env from the example template."
fi

# ---------------------------------------------------------------------------
# Resolve the actual EMBA log directory.
#
# EMBA writes csv_logs/, emba.log, s99_grepit/ ... into its log dir. But users
# often point LAVA at a PARENT folder:
#   fws/DIR880LA/                        <- selected (grandparent, wrong)
#     emba_dir880la1fw1_log/             <- real EMBA log dir
#     lava_scan_.../emba_logs/           <- real EMBA log dir (Full Pipeline layout)
# Without this, the parser silently finds 0 EMBA findings.
# ---------------------------------------------------------------------------
_is_emba_logdir() {
    [ -d "$1/csv_logs" ] || [ -f "$1/emba.log" ] || [ -d "$1/s99_grepit" ] \
        || [ -d "$1/s106_deep_key_search" ] || [ -d "$1/SBOM" ] \
        || [ -d "$1/s26_kernel_vuln_verifier" ]
}

_find_emba_logdirs() {  # prints every EMBA log dir at/under "$1" (depth <= 2)
    local d="$1" c
    _is_emba_logdir "$d" && echo "$d"
    _is_emba_logdir "$d/emba_logs" && echo "$d/emba_logs"
    for c in "$d"/*/; do
        [ -d "$c" ] || continue
        c="${c%/}"
        [ "$c" = "$d/emba_logs" ] && continue
        _is_emba_logdir "$c" && echo "$c"
        _is_emba_logdir "$c/emba_logs" && echo "$c/emba_logs"
    done
}

if ! _is_emba_logdir "$LOGDIR"; then
    mapfile -t _EMBA_CANDIDATES < <(_find_emba_logdirs "$LOGDIR" | sort -u)
    if [ "${#_EMBA_CANDIDATES[@]}" -eq 1 ]; then
        echo "[*] '$LOGDIR' is not an EMBA log directory itself."
        echo "[*] Using the EMBA log directory found inside it: ${_EMBA_CANDIDATES[0]}"
        LOGDIR="${_EMBA_CANDIDATES[0]}"
    elif [ "${#_EMBA_CANDIDATES[@]}" -gt 1 ]; then
        echo "ERROR: '$LOGDIR' contains more than one EMBA log directory."
        echo "       Point LAVA at exactly one of these:"
        printf '           %s\n' "${_EMBA_CANDIDATES[@]}"
        exit 2
    else
        echo "ERROR: '$LOGDIR' is not an EMBA log directory and none was found inside it."
        echo "       (looked for csv_logs/, emba.log, s99_grepit/, s106_deep_key_search/, SBOM/, s26_kernel_vuln_verifier/)"
        echo "       Select the folder EMBA wrote its logs into - not a LAVA output folder."
        exit 2
    fi
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Output goes NEXT TO the EMBA log directory (a sibling), never inside it, and
# the directory name itself carries the timestamp.
#   - EMBA-log-analysis mode (run_lava.sh directly): <parent>/lava_out_<ts>/
#   - full-pipeline mode (run_emba_lava.sh passes -OutDir): the path it gives.
if [ -z "$BASEOUTDIR" ]; then
    _LOGDIR_ABS="$(cd "$LOGDIR" 2>/dev/null && pwd || echo "$LOGDIR")"
    OUTDIR="$(dirname "$_LOGDIR_ABS")/lava_out_$TIMESTAMP"
else
    OUTDIR="$BASEOUTDIR"
fi

# The LAVA pipeline does NOT need root, and in MCP mode the agent CLI (claude /
# agy) plus its login live in the invoking user's home - as root they are not
# found / not logged in ("Authentication required"). So if we were started as
# root via sudo, hand the log dir back to $SUDO_USER and re-run as them.
if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && [ -z "${LAVA_DROPPED:-}" ]; then
    echo "[*] Running the LAVA pipeline as user '$SUDO_USER' (not root)."
    chown -R "$SUDO_USER" "$LOGDIR" 2>/dev/null
    mkdir -p "$OUTDIR" 2>/dev/null && chown -R "$SUDO_USER" "$OUTDIR" 2>/dev/null
    exec sudo -u "$SUDO_USER" -H env LAVA_DROPPED=1 \
        bash -lc 'cd "$1" || exit 1
                  a=(-LogDir "$3" -OutDir "$4"); [ -n "$5" ] && a+=(-Modules "$5")
                  exec bash "$2" "${a[@]}"' \
        lava "$_LAVA_ROOT" "$_SCRIPT" "$LOGDIR" "$OUTDIR" "$_MODULES_FLAG"
fi

# If we are not already inside a venv and the repo has a .venv, activate it.
# (start_linux.sh does this; but when the script is called directly, or after a
# sudo -> privilege drop, VIRTUAL_ENV is empty and packages like `mcp` are missing.)
if [ -z "${VIRTUAL_ENV:-}" ] && [ -x "$_LAVA_ROOT/.venv/bin/python3" ]; then
    # shellcheck disable=SC1091
    source "$_LAVA_ROOT/.venv/bin/activate"
fi

mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"
echo "[*] LAVA output directory: $OUTDIR"
echo "LAVA_OUTPUT_DIR=$OUTDIR"

PID_FILE="$OUTDIR/lava.pid"
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        echo "Warning: a previous scan is still running in this folder (PID: $OLD_PID). Stopping it..."
        kill -9 "$OLD_PID" 2>/dev/null
        sleep 1
    fi
fi
echo $$ > "$PID_FILE"


FINDINGS_FILE="$OUTDIR/findings.json"
MERGED_FILE="$OUTDIR/merged_findings.json"
ENRICHED_FILE="$OUTDIR/enriched_findings.json"
VERDICTS_FILE="$OUTDIR/verdicts.json"
REPORT_FILE="$OUTDIR/lava_report.html"
CUSTOM_FINDINGS_FILE="$OUTDIR/custom_findings.json"
CVE_FINDINGS_FILE="$OUTDIR/cve_findings.json"

# Defaults; overridden from config/ai_config.env below
AI_IP="127.0.0.1"
AI_PORT="11434"
AI_PROVIDER="local"
AI_MODEL="qwen2.5-coder:7b"
CUSTOM_GREP_ENABLED="0"
SCAN_PROFILE="iot-testing"
S99_SCAN="raw"
MCP_BATCH_SIZE="40"
CVE_SCAN_ENABLED="0"

# Read a key's value from ai_config.env. Only matches a line-leading "KEY="
# (skips comment lines such as "# AI_PROVIDER options:"), takes the first
# match, strips quotes and whitespace.
read_env_val() {
    grep -E "^[[:space:]]*$1[[:space:]]*=" "$2" 2>/dev/null | head -n1 \
        | sed -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*[\"']?([^\"']*)[\"']?[[:space:]]*\$/\1/"
}

if [ -f "config/ai_config.env" ]; then
    ip_val=$(read_env_val LOCAL_AI_IP config/ai_config.env)
    port_val=$(read_env_val LOCAL_AI_PORT config/ai_config.env)
    prov_val=$(read_env_val AI_PROVIDER config/ai_config.env)
    mod_val=$(read_env_val LOCAL_AI_MODEL config/ai_config.env)
    grep_val=$(read_env_val CUSTOM_GREP_ENABLED config/ai_config.env)
    profile_val=$(read_env_val SCAN_PROFILE config/ai_config.env)
    s99_val=$(read_env_val S99_SCAN config/ai_config.env)
    batch_val=$(read_env_val MCP_BATCH_SIZE config/ai_config.env)
    cve_val=$(read_env_val CVE_SCAN_ENABLED config/ai_config.env)
    [ -n "$ip_val" ] && AI_IP="$ip_val"
    [ -n "$port_val" ] && AI_PORT="$port_val"
    [ -n "$prov_val" ] && AI_PROVIDER="$prov_val"
    [ -n "$mod_val" ] && AI_MODEL="$mod_val"
    [ -n "$grep_val" ] && CUSTOM_GREP_ENABLED="$grep_val"
    [ -n "$profile_val" ] && SCAN_PROFILE="$profile_val"
    [ -n "$s99_val" ] && S99_SCAN="$s99_val"
    [ -n "$batch_val" ] && MCP_BATCH_SIZE="$batch_val"
    [ -n "$cve_val" ] && CVE_SCAN_ENABLED="$cve_val"
fi

# Which analysis modules to run:
#   credentials -> EMBA S45/S99/S106/S107/S108 (+ optional custom grep) + AI classify
#   cve         -> structure EMBA's F17/S26 CVE output (no AI, no external DB)
# The --modules flag wins outright. Only with NO flag do we fall back to
# "credentials" (+ cve if CVE_SCAN_ENABLED=1).
if [ -n "$_MODULES_FLAG" ]; then
    MODULES="$_MODULES_FLAG"
    _MODULES_SRC="--modules flag"
else
    MODULES="credentials"
    [ "$CVE_SCAN_ENABLED" = "1" ] && MODULES="credentials,cve"
    _MODULES_SRC="default (no --modules flag; CVE_SCAN_ENABLED=$CVE_SCAN_ENABLED)"
fi
case ",$MODULES," in *,credentials,*) RUN_CREDS=1 ;; *) RUN_CREDS=0 ;; esac
case ",$MODULES," in *,cve,*)         RUN_CVE=1   ;; *) RUN_CVE=0   ;; esac
if [ "$RUN_CREDS" = "0" ] && [ "$RUN_CVE" = "0" ]; then
    echo "Error: --modules must include 'credentials' and/or 'cve' (got: '$MODULES')."
    exit 2
fi

# S99_grepit coverage (parser.py reads LAVA_S99_SCAN): raw (default) | light | off
export LAVA_S99_SCAN="$S99_SCAN"

# MCP batching (classifier.py): MCP_BATCH_SIZE=0 -> one giant turn, else batch size
if [ "$MCP_BATCH_SIZE" = "0" ]; then
    export LAVA_MCP_NO_BATCH=1
else
    export LAVA_MCP_BATCH_SIZE="$MCP_BATCH_SIZE"
fi

# --extra-findings / --custom-findings args, populated by the custom grep step
PARSER_EXTRA_ARGS=()
CLASSIFIER_CUSTOM_ARGS=()

# Start Ollama in the background if it is not running (localhost + local provider only).
# Only the credentials module uses the AI; a cve-only run skips this entirely.
if [ "$RUN_CREDS" = "1" ] && [ "$AI_PROVIDER" != "gemini" ] && [[ "$AI_PROVIDER" != mcp* ]] && ! curl -s "http://$AI_IP:$AI_PORT/" > /dev/null; then
    if [ "$AI_IP" = "127.0.0.1" ] || [ "$AI_IP" = "localhost" ]; then
        if command -v ollama &> /dev/null; then
            echo "[AI_INFO] Ollama service is down, starting it in the background..."
            nohup ollama serve > /dev/null 2>&1 &
            sleep 3
            echo "[AI_INFO] Ollama service started."
        else
            echo "ERROR: 'ollama' is not installed on this system."
            echo "Ollama is required to run LAVA in local mode on Linux."
            echo "Install it with: curl -fsSL https://ollama.com/install.sh | sh"
            echo "Alternatively, point config/ai_config.env at a remote Ollama IP."
            exit 2
        fi
    else
        echo "WARNING: could not reach the remote Ollama server ($AI_IP:$AI_PORT)."
        echo "Make sure Ollama is running on the remote host and listening on the network (OLLAMA_HOST=0.0.0.0)."
    fi
fi

echo "========================================="
echo "Starting the LAVA pipeline..."
echo "[AI_INFO] Modules: $MODULES   [$_MODULES_SRC]"
if [ "$RUN_CREDS" = "1" ]; then
  if [ "$AI_PROVIDER" = "gemini" ]; then
    echo "[AI_INFO] Selected model: Gemini API (Cloud)"
  elif [[ "$AI_PROVIDER" == mcp* ]]; then
    echo "[AI_INFO] Selected model: MCP agent ($AI_PROVIDER)"
  else
    echo "[AI_INFO] Selected model: $AI_MODEL (Local AI)"
  fi
fi
if [ "$RUN_CREDS" = "1" ] && [ "$CUSTOM_GREP_ENABLED" = "1" ]; then
    echo "[AI_INFO] Custom grep: ON (profile: $SCAN_PROFILE)"
fi
if [ "$RUN_CREDS" = "1" ]; then
case "$S99_SCAN" in
    raw)              echo "[AI_INFO] S99_grepit coverage: raw (all cryptocred matches; only unreadable binary bytes removed)" ;;
    light|strict|gated|narrow|broad)
                      echo "[AI_INFO] S99_grepit coverage: light (raw minus binary string tables + static web assets)" ;;
    off)              echo "[AI_INFO] S99_grepit coverage: off" ;;
    *)                echo "[AI_INFO] S99_grepit coverage: $S99_SCAN" ;;
esac
if [[ "$AI_PROVIDER" == mcp* ]]; then
    if [ "$MCP_BATCH_SIZE" = "0" ]; then
        echo "[AI_INFO] MCP batching: OFF (single agent turn)"
    else
        echo "[AI_INFO] MCP batching: $MCP_BATCH_SIZE findings/batch"
    fi
fi
fi   # RUN_CREDS info block
echo "========================================="

REPORT_ARGS=()

# =========================================================================
# CREDENTIALS module - EMBA hardcoded-credential findings + AI classification
# =========================================================================
if [ "$RUN_CREDS" = "1" ]; then
    # [1/4] Custom credential grep over the extracted firmware (optional).
    if [ "$CUSTOM_GREP_ENABLED" = "1" ]; then
        echo "[creds 1/4] Running the custom credential grep (profile: $SCAN_PROFILE)..."
        if python3 src/core/custom_scan.py --log-dir "$LOGDIR" --profile "$SCAN_PROFILE" --out "$CUSTOM_FINDINGS_FILE"; then
            PARSER_EXTRA_ARGS=(--extra-findings "$CUSTOM_FINDINGS_FILE")
            CLASSIFIER_CUSTOM_ARGS=(--custom-findings "$CUSTOM_FINDINGS_FILE")
            echo "[OK] Custom grep complete."
        else
            # The custom grep is an optional add-on; its failure must not sink the
            # whole run - carry on with EMBA findings only.
            echo "[!] WARNING: custom_scan.py failed - continuing with EMBA findings only."
        fi
    else
        echo "[creds 1/4] Custom grep: disabled (set CUSTOM_GREP_ENABLED=\"1\" in config/ai_config.env to enable)."
    fi

    if [[ "$AI_PROVIDER" == mcp* ]]; then
        echo "[creds 2-3/4] MCP mode: skipping the parse/enrich steps (the agent explores the raw logs itself)."
    else
        echo -e "\n[creds 2/4] Parsing EMBA logs..."
        python3 src/core/parser.py --log-dir "$LOGDIR" --out "$FINDINGS_FILE" --merged-out "$MERGED_FILE" "${PARSER_EXTRA_ARGS[@]}"
        if [ $? -ne 0 ]; then echo "Error: parser.py failed!"; exit 2; fi
        echo "[OK] Parsing complete."

        echo -e "\n[creds 3/4] Building context (enrich)..."
        python3 src/core/enricher.py --merged "$MERGED_FILE" --log-dir "$LOGDIR" --out "$ENRICHED_FILE"
        if [ $? -ne 0 ]; then echo "Error: enricher.py failed!"; exit 2; fi
        echo "[OK] Context added to findings."
    fi

    echo -e "\n[creds 4/4] Starting LLM classification (this step can take a while)..."
    python3 src/core/classifier.py --mode run --config config/ai_config.env --ground-truth ground_truth.json --enriched "$ENRICHED_FILE" --out "$VERDICTS_FILE" --log-dir "$LOGDIR" "${CLASSIFIER_CUSTOM_ARGS[@]}"
    if [ $? -ne 0 ]; then echo "Error: classifier.py failed!"; exit 2; fi
    echo "[OK] Classification complete. Results written to $VERDICTS_FILE"
    REPORT_ARGS+=(--verdicts "$VERDICTS_FILE")
fi

# =========================================================================
# CVE module - structure EMBA's F17 (component) + S26 (kernel) CVE output
# =========================================================================
if [ "$RUN_CVE" = "1" ]; then
    echo -e "\n[cve] Structuring EMBA's CVE output (F17 + S26)..."
    if python3 src/core/cve_scan.py --log-dir "$LOGDIR" --out "$CVE_FINDINGS_FILE"; then
        echo "[OK] CVE findings written to $CVE_FINDINGS_FILE"
        REPORT_ARGS+=(--cve-findings "$CVE_FINDINGS_FILE")
    else
        # The CVE module is independent; its failure must not sink a run that
        # also asked for the credentials module.
        echo "[!] WARNING: cve_scan.py failed - continuing without the CVE view."
    fi
fi

if [ "${#REPORT_ARGS[@]}" -eq 0 ]; then
    echo -e "\n[!] Nothing to report: no module produced output. Skipping the HTML report."
else
    echo -e "\nGenerating the HTML report..."
    python3 src/reporting/html_report.py "${REPORT_ARGS[@]}" --out "$REPORT_FILE"
    if [ $? -ne 0 ]; then echo "Error: html_report.py failed!"; exit 2; fi
    echo "[OK] Report ready: $REPORT_FILE"
fi

echo -e "\n========================================="
echo "LAVA complete."
echo "========================================="
