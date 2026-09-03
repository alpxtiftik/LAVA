#!/usr/bin/env bash
#
# LAVA full pipeline runner for Linux.
# Runs EMBA and then starts the LAVA AI analysis.

FirmwarePath=""
LogDir=""
Modules=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -FirmwarePath|--firmware-path) FirmwarePath="$2"; shift ;;
        -LogDir|--log-dir) LogDir="$2"; shift ;;
        -Modules|--modules) Modules="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 2 ;;
    esac
    shift
done

if [ -z "$FirmwarePath" ]; then
    echo "Usage: $0 -FirmwarePath <path> [-LogDir <dir>] [-Modules credentials,cve]"
    exit 2
fi

# Forwarded verbatim to run_lava.sh (empty = its default, "credentials").
# NOTE: EMBA still runs its full module set here; -Modules only selects which
# LAVA analysis modules consume the logs afterwards.
MODULES_ARG=()
[ -n "$Modules" ] && MODULES_ARG=(-Modules "$Modules")

# Make the firmware / log-dir paths absolute (they were relative to the caller's
# cwd) - EMBA is invoked after `cd` into its own install dir, so a relative -f/-l
# would resolve against the wrong directory.
case "$FirmwarePath" in
    /*) ;;
    *)  FirmwarePath="$(cd "$(dirname "$FirmwarePath")" 2>/dev/null && pwd)/$(basename "$FirmwarePath")" \
            || FirmwarePath="$PWD/$FirmwarePath" ;;
esac
if [ -n "$LogDir" ]; then
    case "$LogDir" in /*) ;; *) LogDir="$PWD/$LogDir" ;; esac
fi

# EMBA's check_path_input() only accepts [a-zA-Z0-9./_~-] in the -f and -l
# paths and aborts with "Invalid input detected - paths aka ~/abc/def123/ASDF
# only" on anything else (spaces, [], (), +, ...). TP-Link/vendor firmware file
# names routinely contain '[...]'. Sanitize both paths before handing them to EMBA.
_path_ok() { case "$1" in *[!a-zA-Z0-9./_~-]*) return 1 ;; *) return 0 ;; esac; }
_sanitize() { printf '%s' "$1" | sed 's/[^a-zA-Z0-9._-]/_/g'; }

CLEANUP_FW=""
_cleanup() {
    [ -n "${WATCHDOG_PID:-}" ] && kill "$WATCHDOG_PID" 2>/dev/null
    [ -n "$CLEANUP_FW" ] && [ -f "$CLEANUP_FW" ] && rm -f "$CLEANUP_FW"
}
trap _cleanup EXIT

FIRMWARE_DIR=$(dirname "$FirmwarePath")
FIRMWARE_BASENAME=$(basename "$FirmwarePath")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# --- firmware path: hand EMBA a copy at a clean path if needed ---------------
EMBA_FW="$FirmwarePath"
if ! _path_ok "$FirmwarePath"; then
    if _path_ok "$FIRMWARE_DIR"; then _safe_dir="$FIRMWARE_DIR"; else _safe_dir="${TMPDIR:-/tmp}"; fi
    EMBA_FW="${_safe_dir}/lava_fw_${TIMESTAMP}_$(_sanitize "$FIRMWARE_BASENAME")"
    echo "[*] Firmware path has characters EMBA rejects; using a clean copy:"
    echo "    $EMBA_FW"
    ln -f "$FirmwarePath" "$EMBA_FW" 2>/dev/null || cp -f "$FirmwarePath" "$EMBA_FW" || {
        echo "Error: could not create a sanitized copy of the firmware."; exit 2; }
    CLEANUP_FW="$EMBA_FW"
fi

# --- output dirs: EMBA logs and LAVA output as timestamped SIBLINGS ---------
#   <base>/emba_<name>_<ts>/     <- EMBA writes here   (EMBA_DIR)
#   <base>/lava_scan_<name>_<ts>/ <- LAVA writes here  (LAVA_OUT_DIR)
# base = the firmware's own directory, unless it has characters EMBA's
# check_path_input() rejects, in which case ~/.cache/lava/ .
_FW_SANITIZED="$(_sanitize "$FIRMWARE_BASENAME")"
if [ -n "$LogDir" ]; then
    # explicit -LogDir: that IS the EMBA log dir; LAVA output is its sibling
    _OUT_BASE="$(dirname "$LogDir")"
    _path_ok "$_OUT_BASE" || _OUT_BASE="${HOME}/.cache/lava"
    EMBA_DIR="$LogDir"
    _path_ok "$EMBA_DIR" || EMBA_DIR="${_OUT_BASE}/emba_${_FW_SANITIZED}_${TIMESTAMP}"
else
    if _path_ok "$FIRMWARE_DIR"; then _OUT_BASE="$FIRMWARE_DIR"; else _OUT_BASE="${HOME}/.cache/lava"; fi
    EMBA_DIR="${_OUT_BASE}/emba_${_FW_SANITIZED}_${TIMESTAMP}"
fi
LAVA_OUT_DIR="${_OUT_BASE}/lava_scan_${_FW_SANITIZED}_${TIMESTAMP}"
mkdir -p "$_OUT_BASE"
echo "[*] EMBA logs   : $EMBA_DIR"
echo "[*] LAVA output : $LAVA_OUT_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
LAVA_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_ENV="$LAVA_ROOT/config/ai_config.env"

# config/ai_config.env is gitignored; seed it from the template on first run.
if [ ! -f "$CONFIG_ENV" ] && [ -f "$LAVA_ROOT/config/ai_config.example.env" ]; then
    cp "$LAVA_ROOT/config/ai_config.example.env" "$CONFIG_ENV"
    echo "[*] Created config/ai_config.env from the example template."
fi

# Read a line-leading "KEY=" value from ai_config.env (skips comment lines,
# strips quotes/whitespace). Prints nothing if absent.
read_cfg() {
    [ -f "$CONFIG_ENV" ] || return 0
    grep -E "^[[:space:]]*$1[[:space:]]*=" "$CONFIG_ENV" 2>/dev/null | head -n1 \
        | sed -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*[\"']?([^\"']*)[\"']?[[:space:]]*\$/\1/"
}

AI_PROVIDER="$(read_cfg AI_PROVIDER)"; AI_PROVIDER="${AI_PROVIDER:-local}"
CVE_SCAN_ENABLED="$(read_cfg CVE_SCAN_ENABLED)"
EMBA_SCAN_PROFILE="$(read_cfg EMBA_SCAN_PROFILE)"; EMBA_SCAN_PROFILE="${EMBA_SCAN_PROFILE:-auto}"

# Resolve which LAVA modules this run wants (same rule as run_lava.sh): the
# -Modules flag wins; otherwise "credentials" (+ cve if CVE_SCAN_ENABLED=1).
if [ -n "$Modules" ]; then
    RESOLVED_MODULES="$Modules"
else
    RESOLVED_MODULES="credentials"
    [ "$CVE_SCAN_ENABLED" = "1" ] && RESOLVED_MODULES="credentials,cve"
fi
case ",$RESOLVED_MODULES," in *,credentials,*) _R_CREDS=1 ;; *) _R_CREDS=0 ;; esac
case ",$RESOLVED_MODULES," in *,cve,*)         _R_CVE=1   ;; *) _R_CVE=0   ;; esac

# Start Ollama in the background if it is not running
if [ "$AI_PROVIDER" != "gemini" ] && [[ "$AI_PROVIDER" != mcp* ]] && ! curl -s http://localhost:11434/ > /dev/null; then
    echo "Could not reach the Ollama API. Starting it in the background..."
    nohup ollama serve > /dev/null 2>&1 &
    sleep 3
fi

echo "========================================="
echo "STARTING THE LAVA FULL PIPELINE (LINUX)"
echo "========================================="

# If we are not root and there is no terminal to type a sudo password into
# (i.e. started from the GUI), warn instead of hanging on a password prompt.
if [ "$EUID" -ne 0 ] && [ "${LAVA_GUI_MODE:-}" == "1" ]; then
    echo "ERROR: EMBA needs ROOT privileges to run."
    echo "A password cannot be entered from the GUI, so the operation was cancelled."
    echo "FIX: close the UI and re-run the launcher with 'sudo' from a terminal:"
    echo "       sudo bash scripts/start_linux.sh"
    exit 2
fi

# 1. Locate the EMBA executable
EMBA_PATH=""

# Candidate paths (dynamic `command -v` and home-dir scans removed for safety)
CANDIDATE_PATHS=(
    "/emba/emba"
    "/opt/emba/emba"
    "/usr/local/emba/emba"
    "/root/emba/emba"
    "/home/kali/emba/emba"
)

# Read EMBA_PATH from the config file and prepend it (backward compatibility)
if [ -f "$CONFIG_ENV" ]; then
    while IFS='=' read -r key value; do
        if [ "$key" == "EMBA_PATH" ]; then
            config_path=$(echo "$value" | tr -d '"' | tr -d "'")
            CANDIDATE_PATHS=("$config_path" "${CANDIDATE_PATHS[@]}")
        fi
    done < "$CONFIG_ENV"
fi

# Test the candidate paths
for p in "${CANDIDATE_PATHS[@]}"; do
    if [ -n "$p" ]; then
        # If the user gave a directory (e.g. /opt/emba), look for the emba file inside it
        if [ -d "$p" ] && [ -f "$p/emba" ]; then
            p="$p/emba"
        fi

        # Pick it if it exists and is executable
        if [ -x "$p" ]; then
            EMBA_PATH="$p"
            break
        fi
    fi
done

if [ -z "$EMBA_PATH" ]; then
    echo "Error: EMBA executable not found, or it is not executable."
    echo "Make sure EMBA is installed and has the '+x' bit. (Expected at: /opt/emba/emba, /home/kali/emba/emba, etc.)"
    exit 2
fi

if [ ! -f "$FirmwarePath" ]; then
    echo "Error: firmware file not found: $FirmwarePath"
    exit 2
fi

echo "[1/2] Running EMBA..."
echo "Firmware: $FirmwarePath"
[ "$EMBA_FW" != "$FirmwarePath" ] && echo "         (passed to EMBA as: $EMBA_FW)"
echo "EMBA executable: $EMBA_PATH"

emba_dir=$(dirname "$EMBA_PATH")

# ---------------------------------------------------------------------------
# Pick the EMBA scan profile.
#   EMBA_SCAN_PROFILE=full  -> no profile: EMBA runs its complete default set
#                              (slowest, most thorough), whatever modules were
#                              selected. LAVA still only analyses the selected
#                              modules afterwards.
#   EMBA_SCAN_PROFILE=auto  -> a LAVA profile matched to the selected modules,
#                              so EMBA only runs what that module needs:
#       credentials      -> lava.00-quick-scan.emba
#       cve              -> lava.01-cve-scan.emba
#       credentials,cve  -> lava.02-full-lava-scan.emba
# ---------------------------------------------------------------------------
_PROF_DIR="$LAVA_ROOT/EMBA - Scan Profile"
if [ "$EMBA_SCAN_PROFILE" = "full" ]; then
    echo "EMBA scan profile: full (EMBA's complete default scan; modules selected: $RESOLVED_MODULES)"
    PROFILE_ARG=""
else
    if [ "$_R_CREDS" = "1" ] && [ "$_R_CVE" = "1" ]; then
        _PROF="lava.02-full-lava-scan.emba"
    elif [ "$_R_CVE" = "1" ]; then
        _PROF="lava.01-cve-scan.emba"
    else
        _PROF="lava.00-quick-scan.emba"
    fi
    if [ -f "$_PROF_DIR/$_PROF" ]; then
        echo "EMBA scan profile: auto -> $_PROF  (modules: $RESOLVED_MODULES)"
        sudo mkdir -p "$emba_dir/scan-profiles/"
        sudo cp "$_PROF_DIR/$_PROF" "$emba_dir/scan-profiles/"
        PROFILE_ARG="-p $_PROF"
    else
        echo "Warning: profile '$_PROF' not found, falling back to EMBA's default scan."
        PROFILE_ARG=""
    fi
fi

# EMBA_DIR and LAVA_OUT_DIR were set at the top (timestamped siblings).

# --- Entropy-graph watchdog --------------------------------------------------
# EMBA's P02 draws a firmware entropy graph with `binwalk --entropy --png`, which
# shells out to Plotly Kaleido (headless Chromium). On some hosts Chromium
# deadlocks inside the EMBA container and, because P02 waits for binwalk
# synchronously, the whole scan hangs there forever. The graph is cosmetic, so
# if that binwalk has been running longer than ENTROPY_WATCHDOG_TIMEOUT seconds
# we kill it (and any Kaleido child); EMBA then logs a warning and moves on.
ENTROPY_WATCHDOG_TIMEOUT="${ENTROPY_WATCHDOG_TIMEOUT:-90}"

_wd_kill() { kill -9 "$@" 2>/dev/null || sudo -n kill -9 "$@" 2>/dev/null; }

_entropy_watchdog() {
    while sleep 15; do
        # Match EMBA's exact P02 invocation ("binwalk --entropy --png ...").
        # The [b] class keeps this pgrep from matching its own command line.
        for _pid in $(pgrep -f '[b]inwalk --entropy --png' 2>/dev/null); do
            [ "$_pid" = "$$" ] && continue                       # never our own process
            _comm=$(ps -o comm= -p "$_pid" 2>/dev/null)
            case "$_comm" in bash|sh|dash|python3|pgrep|"") continue ;; esac  # only real binwalk
            _secs=$(ps -o etimes= -p "$_pid" 2>/dev/null | tr -d ' ')
            [ -n "$_secs" ] || continue
            if [ "$_secs" -gt "$ENTROPY_WATCHDOG_TIMEOUT" ]; then
                echo ""
                echo "[watchdog] EMBA entropy step stuck for ${_secs}s (binwalk pid $_pid)."
                echo "[watchdog] Killing it - Plotly/Kaleido/Chromium deadlock. The scan will continue."
                _wd_kill "$_pid"
                for _k in $(pgrep -f 'kaleido' 2>/dev/null); do _wd_kill "$_k"; done
            fi
        done
    done
}

_entropy_watchdog &
WATCHDOG_PID=$!

# Run EMBA directly. Python's PTY will handle the terminal dimensions and UTF-8 base64 encoding.
cd "$emba_dir"
sudo LC_ALL="en_US.UTF-8" LANG="en_US.UTF-8" ./emba -f "$EMBA_FW" -l "$EMBA_DIR" $PROFILE_ARG
EMBA_RC=$?

kill "$WATCHDOG_PID" 2>/dev/null; WATCHDOG_PID=""

if [ "$EMBA_RC" -ne 0 ]; then
    echo "Error: the EMBA scan failed, or EMBA was not found."
    exit 2
fi

echo "[OK] EMBA scan complete."

# 3. Start the LAVA analysis.
# The EMBA log directory was created by root; LAVA (and, in MCP mode, the agent
# CLI) runs as a normal user, so hand ownership back.
# Under `sudo`, $USER is root; get the real user from $SUDO_USER.
TARGET_USER="${SUDO_USER:-$USER}"
sudo chown -R "$TARGET_USER:$TARGET_USER" "$EMBA_DIR" 2>/dev/null
mkdir -p "$LAVA_OUT_DIR" && sudo chown -R "$TARGET_USER:$TARGET_USER" "$LAVA_OUT_DIR" 2>/dev/null

echo ""
echo "[2/2] Starting the LAVA AI analysis..."
cd "$LAVA_ROOT" || exit 2

# The LAVA AI analysis does not need root. In MCP mode the agent CLIs (claude /
# agy) and the venv are per-user; they are invisible in root's PATH/HOME. So if
# this script is running as root, run the analysis step as the real user.
if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    echo "[*] Running the AI analysis as user '$SUDO_USER' (not root)."
    sudo -u "$SUDO_USER" -H bash -lc \
        'root="$1"; log="$2"; out="$3"; shift 3; cd "$root" || exit 2
         exec bash scripts/run_lava.sh -LogDir "$log" -OutDir "$out" "$@"' \
        lava-analysis "$LAVA_ROOT" "$EMBA_DIR" "$LAVA_OUT_DIR" "${MODULES_ARG[@]}"
    lava_rc=$?
else
    bash "$SCRIPT_DIR/run_lava.sh" -LogDir "$EMBA_DIR" -OutDir "$LAVA_OUT_DIR" "${MODULES_ARG[@]}"
    lava_rc=$?
fi

if [ $lava_rc -ne 0 ]; then
    echo "Error: the LAVA AI analysis step (run_lava.sh) failed. Check the LAVA logs for details."
    exit 2
fi

echo ""
echo "========================================="
echo "FULL PIPELINE COMPLETE."
echo "========================================="
