#!/usr/bin/env bash
#
# LAVA full pipeline runner for Linux.
# Runs EMBA and then starts the LAVA AI analysis.

FirmwarePath=""
LogDir=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -FirmwarePath|--firmware-path) FirmwarePath="$2"; shift ;;
        -LogDir|--log-dir) LogDir="$2"; shift ;;
        *) echo "Unknown parameter: $1"; exit 2 ;;
    esac
    shift
done

if [ -z "$FirmwarePath" ]; then
    echo "Usage: $0 -FirmwarePath <path> [-LogDir <dir>]"
    exit 2
fi

if [ -z "$LogDir" ]; then
    FIRMWARE_DIR=$(dirname "$FirmwarePath")
    FIRMWARE_BASENAME=$(basename "$FirmwarePath")
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    LogDir="${FIRMWARE_DIR}/lava_scan_${FIRMWARE_BASENAME}_${TIMESTAMP}"
    echo "[*] -LogDir not given, using: $LogDir"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
LAVA_ROOT="$(dirname "$SCRIPT_DIR")"

AI_PROVIDER="local"
if [ -f "$LAVA_ROOT/config/ai_config.env" ]; then
    # Only match a line-leading "AI_PROVIDER="; skip comment lines such as
    # "# AI_PROVIDER options:", take the first match, strip quotes/whitespace.
    prov_val=$(grep -E "^[[:space:]]*AI_PROVIDER[[:space:]]*=" "$LAVA_ROOT/config/ai_config.env" 2>/dev/null | head -n1 \
        | sed -E "s/^[[:space:]]*AI_PROVIDER[[:space:]]*=[[:space:]]*[\"']?([^\"']*)[\"']?[[:space:]]*\$/\1/")
    [ -n "$prov_val" ] && AI_PROVIDER="$prov_val"
fi

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
	"/home/ahtiftik/emba"
)

# Read EMBA_PATH from the config file and prepend it (backward compatibility)
if [ -f "config/ai_config.env" ]; then
    while IFS='=' read -r key value; do
        if [ "$key" == "EMBA_PATH" ]; then
            config_path=$(echo "$value" | tr -d '"' | tr -d "'")
            CANDIDATE_PATHS=("$config_path" "${CANDIDATE_PATHS[@]}")
        fi
    done < "config/ai_config.env"
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
echo "Parent directory (LAVA & EMBA): $LogDir"
echo "EMBA directory: $EMBA_PATH"

emba_dir=$(dirname "$EMBA_PATH")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
LAVA_ROOT="$(dirname "$SCRIPT_DIR")"
PROFILE_SRC="$LAVA_ROOT/EMBA - Scan Profile/lava.00-quick-scan.emba"

if [ -f "$PROFILE_SRC" ]; then
    echo "Quick-scan profile found, copying: $PROFILE_SRC"
    sudo mkdir -p "$emba_dir/scan-profiles/"
    sudo cp "$PROFILE_SRC" "$emba_dir/scan-profiles/"
    PROFILE_ARG="-p lava.00-quick-scan.emba"
else
    echo "Warning: quick-scan profile not found, using EMBA's default scan."
    PROFILE_ARG=""
fi

# Set up directories
PARENT_DIR="$LogDir"
EMBA_DIR="$PARENT_DIR/emba_logs"
LAVA_OUT_DIR="$PARENT_DIR/lava_out"

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
trap '[ -n "${WATCHDOG_PID:-}" ] && kill "$WATCHDOG_PID" 2>/dev/null' EXIT

# Run EMBA directly. Python's PTY will handle the terminal dimensions and UTF-8 base64 encoding.
cd "$emba_dir"
sudo LC_ALL="en_US.UTF-8" LANG="en_US.UTF-8" ./emba -f "$FirmwarePath" -l "$EMBA_DIR" $PROFILE_ARG
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
sudo chown -R "$TARGET_USER:$TARGET_USER" "$PARENT_DIR" 2>/dev/null

echo ""
echo "[2/2] Starting the LAVA AI analysis..."
cd "$LAVA_ROOT" || exit 2

# The LAVA AI analysis does not need root. In MCP mode the agent CLIs (claude /
# agy) and the venv are per-user; they are invisible in root's PATH/HOME. So if
# this script is running as root, run the analysis step as the real user.
if [ "$EUID" -eq 0 ] && [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    echo "[*] Running the AI analysis as user '$SUDO_USER' (not root)."
    sudo -u "$SUDO_USER" -H bash -lc \
        'cd "$1" && exec bash scripts/run_lava.sh -LogDir "$2" -OutDir "$3"' \
        lava-analysis "$LAVA_ROOT" "$EMBA_DIR" "$LAVA_OUT_DIR"
    lava_rc=$?
else
    bash "$SCRIPT_DIR/run_lava.sh" -LogDir "$EMBA_DIR" -OutDir "$LAVA_OUT_DIR"
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
