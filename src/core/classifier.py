#!/usr/bin/env python3
"""
LAVA - LLM classifier
=====================
Classifies every hardcoded-credential finding in enriched_findings.json (or the
test_set in ground_truth.json) as TP/FP by asking an AI provider.

Two modes:
  test  -> runs the test_set from ground_truth.json, compares against the real
           labels and reports accuracy/precision/recall.
  run   -> produces a verdict for ALL findings in enriched_findings.json, no
           comparison (no ground-truth labels).

Usage:
    # Test mode - measured against the answer key
    python3 classifier.py --mode test --config config/ai_config.env \\
        --ground-truth ground_truth.json --out verdicts_test.json

    # Run mode - the real pipeline
    python3 classifier.py --mode run --config config/ai_config.env \\
        --enriched enriched_findings.json --out verdicts.json
"""

import os
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

from parser import _derive_source  # 'emba' | 'custom' | 'both' from a module list

# Constants for the MCP (agentic) provider mode
# --------------------------------------------------------------------------
# Upper time limit for the headless agent (claude / agy) run. On timeout the
# subprocess is terminated and reported as an error (no risk of hanging forever).
AGENT_TIMEOUT_SECONDS = int(os.environ.get("LAVA_AGENT_TIMEOUT_SECONDS", str(60 * 60)))
MCP_SERVER_PATH = Path(__file__).resolve().parents[2] / "src" / "mcp" / "lava_mcp_server.py"
# In MCP mode the agent gets EVERY finding in one context. Above this it reliably
# times out on real firmware (S99_grepit alone can be 1000+ findings). Override
# with LAVA_MCP_FORCE=1.
MCP_MAX_FINDINGS = int(os.environ.get("LAVA_MCP_MAX_FINDINGS", "120"))
# Fields that MUST be present in verdicts.json (local/Gemini run-mode schema)
_VERDICT_REQUIRED_FIELDS = {
    "file_path", "matched_content", "predicted_verdict", "confidence", "model_reasoning",
}

def atomic_save(data: dict | list, file_path: str):
    path = Path(file_path)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp_path, path)

# ---------------------------------------------------------------------------
# A fixed reminder note for the model so small models do not confuse the hash
# format prefixes. All formats seen in EMBA's S107/S108 output are here.
# ---------------------------------------------------------------------------
HASH_CHEATSHEET = """\
Known crypt() hash format prefixes (these are REAL, working hashes, strong TP signal):
  $1$  -> MD5-crypt
  $5$  -> SHA-256-crypt
  $6$  -> SHA-512-crypt
  $2a$/$2b$/$2y$ -> bcrypt
If a line in /etc/passwd or /etc/shadow contains one of these prefixes and has the correct
number of fields (user:hash:lastchg:min:max:warn:inactive:expire), it is generally a real TP."""

SYSTEM_PROMPT_TEMPLATE = """You are a firmware security analyst. Your task is to review "hardcoded \
credential/secret" candidates found by the EMBA firmware analysis tool and decide whether each one \
is a REAL credential leak (TP - True Positive) or a false alarm (FP - False Positive).

{hash_cheatsheet}

When evaluating, pay attention to:
- The file path (is it a config file, a binary/library, a script, or UI code?)
- Whether the matched content is an ACTUAL value, or just a variable name/definition/comment/UI label
- How many different EMBA modules independently confirmed the same finding (corroboration_count) - higher means a stronger TP signal
- The provided file context (context_lines) - the code/config surrounding the matched line

CRITICAL RULES:
1. If the "matched content" is not a concrete value but a GENERIC module message
   (e.g. "flagged as password-related file" - this is a file classification flag,
   NOT the file's actual content), this alone does NOT count as TP evidence. In this case,
   decide based on the PROVIDED CONTEXT: if you see an actual hash/password VALUE in the
   context, say TP; if not (e.g. all lines contain 'x' or '*' placeholders, or no context
   was found at all), say FP.
2. If the matched code reads from a VARIABLE or is CONDITIONAL provisioning/script logic
   (e.g. "json_get_vars root_password_hash", "sed -i ... /etc/shadow", code that reads a
   value from a config file and applies it if present), this is NOT itself a hardcoded
   credential - the script is merely APPLYING a value coming from another source (board.json,
   config). This is generally FP, because the actual value is not in this file, but in the
   source the script reads from.
3. If the context shows "exact_match_located: false", remember that this context was taken
   from the BEGINNING of the file and does not represent the actual matched line - evaluate
   more cautiously accordingly, and do not say TP just by trusting the file name.
4. If the matched content is in /etc/passwd or /etc/shadow format (e.g. "root:x:0:0...")
   but does NOT contain an actual cryptographic hash starting with $1$, $5$, $6$, $2a$, etc.,
   this is DEFINITELY an FP. Characters like 'x' or '*' are merely placeholders and are NOT
   hashes. Only lines containing an actual, long hash are TP.
5. A private key found in firmware (RSA/EC/DSA, in "-----BEGIN ... PRIVATE KEY-----" format)
   should be treated as TP BY DEFAULT - the fact that the key has a valid/real cryptographic
   format is evidence THAT it is genuine cryptographic material, not evidence that it is safe.
   The only thing that makes a private key FP is CONCRETE evidence that it is explicitly a
   test/example/documentation key (e.g. an OBVIOUS marker such as "example", "test", "sample",
   "dummy" in the file name/path, AND it must be clearly part of the vendor's own build process -
   the "-----BEGIN ... PRIVATE KEY-----" format alone can NEVER be used as FP justification).
   When in doubt, say TP.

A NOTE ON THE MODULE FIELD:
- Modules named "S45", "S99", "S106", "S107", "S108" are EMBA's own modules.
- Modules named "CUSTOM:<rule>" are LAVA's own regex rules, aimed at cleartext
  credentials EMBA tends to miss. For a CUSTOM finding, an "extracted candidate
  value" is usually provided - that is the exact secret the rule captured;
  evaluate whether that value is a real, usable credential (not a placeholder,
  variable reference, example, or empty string).
- If a finding was confirmed by BOTH an EMBA module and a CUSTOM rule, that is a
  strong TP signal.

Below are examples. Learn from them, then evaluate the NEW finding given to you.

{few_shot_block}

VERY IMPORTANT RULES:
1. Write the "reasoning" field STRICTLY AND ONLY IN ENGLISH.
2. Respond ONLY in the following JSON format, with no other text:
{{"verdict": "TP" or "FP", "confidence": a number between 0.0-1.0, "reasoning": "1-2 sentence short ENGLISH reasoning"}}
"""

FEW_SHOT_ITEM_TEMPLATE = """### Example {n}
File: {file_path}
Module: {module}
Matched content: {matched_content}
Correct answer: {{"verdict": "{verdict}", "confidence": 0.99, "reasoning": "{reasoning}"}}
"""

USER_PROMPT_TEMPLATE = """Now evaluate this finding:

File: {file_path}
Module: {module}
Number of modules that confirmed this (corroboration_count): {corroboration_count}
Matched content: {matched_content}
{value_line}{context_block}
Respond only in the requested JSON format."""


# ---------------------------------------------------------------------------
# Config reading - fully compatible with EMBA's config/ai_config.env format
# (bash env lines of the form KEY="value")
# ---------------------------------------------------------------------------
def load_ai_config(config_path: Path) -> dict:
    config = {
        "AI_PROVIDER": "local",
        "GEMINI_API_KEY": "",
        "LOCAL_AI_IP": "127.0.0.1",
        "LOCAL_AI_MODEL": "",
        "AI_MAX_CHARS_TO_ANALYSE": "5000",
        "LOCAL_AI_PORT": "11434",
    }
    if not config_path.exists():
        return config
    line_re = re.compile(r'^\s*([A-Z_]+)\s*=\s*"?([^"\n]*)"?\s*$')
    for line in config_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = line_re.match(line)
        if m:
            config[m.group(1)] = m.group(2)
    return config


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------
def format_context_block(context: dict | None, max_chars: int) -> str:
    if not context or context.get("status") != "ok":
        status = (context or {}).get("status", "no_context")
        return f"File context: not available ({status})\n"
    lines = context["context_lines"]
    idx = context.get("matched_line_index_in_context")
    exact = context.get("exact_match_located", idx is not None)
    rendered = []
    for i, ln in enumerate(lines):
        marker = ">>> " if (exact and i == idx) else "    "
        rendered.append(f"{marker}{ln}")
    block = "\n".join(rendered)
    if len(block) > max_chars:
        block = block[:max_chars] + "\n... (truncated)"
    note = "" if exact else "\n[NOTE: the matched line could not be located exactly; this is a sample from the START of the file - there is NO '>>>' marker, decide based on the content yourself]"
    return f"File context{' (>>> = matched line)' if exact else ''}:{note}\n{block}\n"


def build_few_shot_block(few_shot_items: list[dict]) -> str:
    parts = []
    for i, item in enumerate(few_shot_items, start=1):
        parts.append(
            FEW_SHOT_ITEM_TEMPLATE.format(
                n=i,
                file_path=item["file_path"],
                module=item["module"],
                matched_content=item["matched_content"],
                verdict=item["verdict"],
                reasoning=item.get("reasoning", ""),
            )
        )
    return "\n".join(parts)


def build_system_prompt(few_shot_items: list[dict]) -> str:
    return SYSTEM_PROMPT_TEMPLATE.format(
        hash_cheatsheet=HASH_CHEATSHEET,
        few_shot_block=build_few_shot_block(few_shot_items),
    )


def build_user_prompt(item: dict, max_chars: int) -> str:
    module = item.get("module") or ", ".join(item.get("found_by_modules", []) or []) or "?"
    value = (item.get("extra") or {}).get("value")
    value_line = f"Extracted candidate value: {str(value)[:max_chars]}\n" if value else ""
    return USER_PROMPT_TEMPLATE.format(
        file_path=item["file_path"],
        module=module,
        corroboration_count=item.get("corroboration_count", "?"),
        matched_content=item["matched_content"][:max_chars],
        value_line=value_line,
        context_block=format_context_block(item.get("context"), max_chars),
    )


# ---------------------------------------------------------------------------
# LocalAI call - same endpoint/format as the curl call in
# Q03_localai_connector.sh (OpenAI-compatible /v1/chat/completions)
# ---------------------------------------------------------------------------
def call_localai(base_url: str, model: str, system_prompt: str, user_prompt: str, timeout: int = 600) -> str | None:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
    }
    try:
        resp = requests.post(
            f"{base_url}/v1/chat/completions",
            json=payload,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except (requests.RequestException, KeyError, IndexError, ValueError) as e:
        print(f"    [!] LocalAI call error: {e}")
        return None

class RateLimitException(Exception):
    def __init__(self, delay):
        self.delay = delay
        super().__init__(f"Rate limit exceeded, must wait {delay} seconds.")

def call_gemini(api_key: str, system_prompt: str, user_prompt: str, timeout: int = 60) -> str | None:
    if not api_key:
        print("    [!] Gemini API key (GEMINI_API_KEY) is missing.")
        return None
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={api_key}"
    payload = {
        "system_instruction": {
            "parts": [{"text": system_prompt}]
        },
        "contents": [{
            "parts": [{"text": user_prompt}]
        }],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json"
        }
    }
    try:
        resp = requests.post(url, json=payload, timeout=timeout, headers={"Content-Type": "application/json"})
        if resp.status_code == 429:
            delay = 15.0
            try:
                data = resp.json()
                for detail in data.get("error", {}).get("details", []):
                    if "retryDelay" in detail:
                        delay = float(detail["retryDelay"].replace("s", "")) + 1.0
            except Exception:
                pass
            raise RateLimitException(delay)

        resp.raise_for_status()
        data = resp.json()
        if "candidates" in data and len(data["candidates"]) > 0:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        return None
    except requests.RequestException as e:
        error_msg = ""
        if hasattr(e, "response") and e.response is not None:
            error_msg = f" API response: {e.response.text}"
        print(f"    [!] Gemini network error: {e}{error_msg}")
        return None
    except (KeyError, IndexError, ValueError) as e:
        print(f"    [!] Gemini data error: {e}")
        return None

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


def parse_verdict_response(raw_text: str) -> dict | None:
    if not raw_text:
        return None
    m = _JSON_BLOCK_RE.search(raw_text)
    if not m:
        return None
    try:
        parsed = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    verdict = str(parsed.get("verdict", "")).strip().upper()
    if verdict not in ("TP", "FP"):
        return None

    conf_raw = parsed.get("confidence")
    conf = 0.0
    if conf_raw is not None:
        try:
            conf_val = float(conf_raw)
            if conf_val > 1.0:
                conf = conf_val / 100.0  # Normalize 80 to 0.80
            else:
                conf = conf_val
        except (ValueError, TypeError):
            pass

    return {
        "verdict": verdict,
        "confidence": conf,
        "reasoning": parsed.get("reasoning", ""),
    }


def classify_item(
    item: dict,
    config: dict,
    system_prompt: str,
    max_chars: int,
    max_retries: int = 3,
) -> dict:
    user_prompt = build_user_prompt(item, max_chars)
    provider = config.get("AI_PROVIDER", "local")
    base_url = f"http://{config['LOCAL_AI_IP']}:{config['LOCAL_AI_PORT']}"
    model = config.get("LOCAL_AI_MODEL", "")
    gemini_key = config.get("GEMINI_API_KEY", "")

    # Log which provider is used before the first attempt
    if not hasattr(classify_item, "provider_logged"):
        print(f"\n[+] Using AI Provider: {provider.upper()}")
        classify_item.provider_logged = True

    last_error_details = ""
    for attempt in range(1, max_retries + 1):
        try:
            if provider == "gemini":
                raw = call_gemini(gemini_key, system_prompt, user_prompt)
            else:
                raw = call_localai(base_url, model, system_prompt, user_prompt)
        except RateLimitException as e:
            last_error_details = str(e)
            print(f"    [!] Attempt {attempt}/{max_retries} failed ({provider.upper()}). Quota exceeded. Waiting {e.delay}s...")
            time.sleep(e.delay)
            continue

        result = parse_verdict_response(raw) if raw else None
        if result is not None:
            result["attempts"] = attempt
            return result

        last_error_details = "Raw response: None" if not raw else f"Raw response: {raw.strip()[:200]}..."
        print(f"    [!] Attempt {attempt}/{max_retries} failed ({provider.upper()}). Error detail: {last_error_details}")
        if attempt < max_retries:
            print("        Retrying (2s)...")
            time.sleep(2)

    return {"verdict": "ERROR", "confidence": None, "reasoning": f"No valid response from the {provider.upper()} API. {last_error_details}", "attempts": max_retries}



# ---------------------------------------------------------------------------
# MCP (agentic) provider mode
# ---------------------------------------------------------------------------
# In local/Gemini mode this is where requests.post(...) calls Ollama/Gemini.
# In MCP mode the equivalent is: register lava_mcp_server.py as an MCP server,
# launch the chosen CLI (claude / agy) headless, and wait for it to finish. The
# agent explores on its own via the MCP tools and writes the verdicts straight
# to verdicts.json (the schema is identical to local/Gemini).
# ---------------------------------------------------------------------------

def _build_agent_prompt(ground_truth_path: str | None) -> str:
    """The task prompt for the agent. The classification rules / few-shot come
    from the SAME source as local/Gemini mode (build_system_prompt)."""
    few_shot: list[dict] = []
    if ground_truth_path and Path(ground_truth_path).exists():
        try:
            data = json.loads(Path(ground_truth_path).read_text(encoding="utf-8"))
            few_shot = data.get("few_shot", []) or []
        except (json.JSONDecodeError, OSError):
            pass

    rules = build_system_prompt(few_shot)
    return f"""{rules}

=== TASK (MCP agent mode) ===
You are connected to the LAVA MCP server. Its tools are prefixed `mcp__lava__`
(a.k.a. the "lava" server). Work fully autonomously - do NOT ask questions.

Steps:
1. Call `list_findings` to get the findings you must classify, each with its
   `finding_id`. For large firmware this is a WINDOW of the full set (e.g.
   "findings 41-80 of 350") - classify exactly what it returns, no more, no less.
2. Call `get_hardcoded_keys_module_output` ONCE to read the raw EMBA module output.
3. Decide TP or FP for EVERY finding using the rules above. For most findings you
   already have enough: file_path, matched_content, candidate_value, source and
   corroboration_count. Use `read_firmware_file` / `search_log_content` ONLY for
   the genuinely ambiguous ones (is this value real or a placeholder / does the
   script actually use it). Do NOT read a file for every finding - be economical,
   especially when there are many findings.
4. Write results with ONE `submit_all_verdicts` call: a list of
   {{"finding_id": ..., "verdict": "TP"|"FP", "confidence": 0.0-1.0,
     "reasoning": "1-2 sentence English"}}.
   (Use `submit_verdict` only for follow-up corrections.)

Every finding_id returned by `list_findings` must receive a verdict.
When all verdicts are written, stop.
"""


def _mcp_config_dict(log_dir: str, fw_root: str, verdicts_out: str,
                     custom_findings: str | None = None,
                     findings_offset: int = 0, findings_limit: int = 0) -> dict:
    args = [
        str(MCP_SERVER_PATH),
        "--log-dir", log_dir,
        "--fw-root", fw_root,
        "--verdicts-out", verdicts_out,
    ]
    if custom_findings:
        args += ["--custom-findings", custom_findings]
    if findings_offset > 0 or (findings_limit and findings_limit > 0):
        args += ["--findings-offset", str(max(0, findings_offset)),
                 "--findings-limit", str(findings_limit if findings_limit and findings_limit > 0 else 0)]
    return {"mcpServers": {"lava": {"command": sys.executable, "args": args}}}


_MCP_TOOL_NAMES = [
    "list_findings", "get_hardcoded_keys_module_output", "list_log_files",
    "read_log_file", "read_firmware_file", "search_log_content",
    "submit_verdict", "submit_all_verdicts",
]


def _resolve_cli(name: str) -> str:
    """Looks for the CLI on PATH, then in common install locations (the installer
    may have skipped adding it to PATH / the shell was not restarted)."""
    found = shutil.which(name)
    if found:
        return found

    # Candidate HOME directories. When running under `sudo` (EMBA needs root but
    # claude/agy are per-user), Path.home() is usually /root; also scan the real
    # user's HOME.
    homes: list[Path] = [Path.home()]
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            import pwd  # POSIX
            homes.append(Path(pwd.getpwnam(sudo_user).pw_dir))
        except KeyError:
            homes.append(Path("/home") / sudo_user)

    candidates: list[Path] = []
    for home in homes:
        candidates += [
            home / ".local" / "bin" / name,
            home / ".npm-global" / "bin" / name,
            home / "bin" / name,
        ]
    candidates += [
        Path("/usr/local/bin") / name,
        Path("/opt") / name / "bin" / name,
    ]
    for c in candidates:
        try:
            if c.is_file():
                return str(c)
        except OSError:  # unreadable candidate (e.g. another user's /root)
            continue
    return name


_AUTH_HINTS = (
    "authentication required", "authentication timed out", "please visit the url to log in",
    "oauth access token is invalid", "oauth token", "not logged in",
    "please log in", "please login", "run `claude`", "run `agy`", "you are not authenticated",
)


def _estimate_finding_count(log_dir: Path, custom_findings: str | None) -> int:
    """Rough count of the findings the MCP registry will hold (EMBA + custom),
    using the same parser functions the MCP server uses."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import parser as _p  # src/core/parser.py
        csv = log_dir / "csv_logs"
        raw = []
        raw += _p.parse_s45(csv / "s45_pass_file_check.csv")
        raw += _p.parse_s107(csv / "s107_deep_password_search.csv")
        raw += _p.parse_s108(log_dir / "s108_stacs_password_search" / "stacs_pw_hashes.json")
        raw += _p.parse_s106(log_dir / "s106_deep_key_search")
        raw += _p.parse_s99(log_dir / "s99_grepit")
        if custom_findings and Path(custom_findings).exists():
            extra = json.loads(Path(custom_findings).read_text(encoding="utf-8"))
            if isinstance(extra, list):
                raw += extra
        return len(_p.merge_and_corroborate(raw))
    except Exception:  # noqa: BLE001 - a bad estimate must not block the run
        return 0


def _raise_if_auth_error(text: str, cli_name: str) -> None:
    low = (text or "").lower()
    if any(h in low for h in _AUTH_HINTS):
        raise RuntimeError(
            f"'{cli_name}' is not authenticated (its OAuth token likely expired). "
            f"MCP mode cannot log in headlessly. Fix: open a terminal, run `{cli_name}`, "
            f"log in, then re-run the scan. (If you started LAVA with sudo, log in as "
            f"your normal user - the login is per-user, not root.)"
        )


def _auth_preflight(agent: str, exe: str, cli_name: str, cwd: str) -> None:
    """Cheap check that the agent CLI is logged in, so a stale token fails here
    (seconds) instead of after the full agent run (minutes)."""
    if agent in ("antigravity", "mcp_antigravity", "agy", "gemini_cli"):
        probe = [exe, "--output-format", "json", "-p", "reply with the single word OK"]
        stdin = None
    else:
        probe = [exe, "-p", "--output-format", "json"]
        stdin = "reply with the single word OK"
    try:
        r = subprocess.run(probe, input=stdin, cwd=cwd,
                           capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"'{cli_name}' did not respond within 90s on a trivial prompt - it is most "
            f"likely waiting for an interactive login. Run `{cli_name}` in a terminal, "
            f"log in, then re-run the scan."
        )
    _raise_if_auth_error((r.stderr or "") + (r.stdout or ""), cli_name)


def _build_agent_command(
    agent: str, prompt: str, mcp_config_path: str,
) -> tuple[list[str], str | None, list[list[str]], list[list[str]]]:
    """Returns: (main_command, stdin_text, pre_commands, cleanup_commands).

    The prompt is multi-line, so it is passed via stdin rather than argv where possible.
    """
    if agent in ("claude", "mcp_claude"):
        # --allowedTools is variadic; "mcp__lava" = all tools of the server.
        allowed = ["mcp__lava", *(f"mcp__lava__{t}" for t in _MCP_TOOL_NAMES)]
        cmd = [
            _resolve_cli("claude"), "-p",
            "--output-format", "json",
            "--permission-mode", "acceptEdits",
            "--strict-mcp-config",
            "--mcp-config", mcp_config_path,
            "--allowedTools", *allowed,  # keep last so it does not swallow the next arg
        ]
        return cmd, prompt, [], []  # prompt via stdin

    if agent in ("antigravity", "mcp_antigravity", "agy", "gemini_cli"):
        agy = _resolve_cli("agy")
        cfg = json.loads(Path(mcp_config_path).read_text(encoding="utf-8"))
        srv = cfg["mcpServers"]["lava"]
        # agy has no --mcp-config; add/update the persistent config, then remove it.
        pre = [[agy, "mcp", "add", "lava", "--", srv["command"], *srv["args"]]]
        post = [[agy, "mcp", "remove", "lava"]]
        # agy takes the next arg as the prompt for -p -> keep it last.
        cmd = [
            agy,
            "--dangerously-skip-permissions",
            "--output-format", "json",
            "--mode", "accept-edits",
            "-p", prompt,
        ]
        return cmd, None, pre, post

    raise ValueError(f"Unknown MCP agent: {agent!r} (expected: 'claude' | 'antigravity')")


def _validate_verdicts_schema(verdicts_path: str) -> int:
    """Validates that verdicts.json has the same schema as local/Gemini mode.
    Returns: the number of verdicts."""
    p = Path(verdicts_path)
    if not p.exists():
        raise RuntimeError(f"The agent run finished but verdicts.json was not written: {verdicts_path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise RuntimeError(f"verdicts.json could not be read / is invalid JSON: {e}") from e
    if not isinstance(data, list) or not data:
        raise RuntimeError("verdicts.json is not a list or is empty (the agent wrote no verdicts).")
    for i, rec in enumerate(data):
        if not isinstance(rec, dict):
            raise RuntimeError(f"verdicts.json[{i}] is not an object.")
        missing = _VERDICT_REQUIRED_FIELDS - set(rec)
        if missing:
            raise RuntimeError(f"verdicts.json[{i}] missing field(s): {sorted(missing)}")
        if str(rec["predicted_verdict"]).upper() not in ("TP", "FP", "ERROR"):
            raise RuntimeError(
                f"verdicts.json[{i}] invalid predicted_verdict: {rec['predicted_verdict']!r}"
            )
    return len(data)


def classify_via_mcp_agent(
    log_dir: str,
    fw_root: str,
    out_path: str,
    agent: str = "claude",
    ground_truth_path: str | None = None,
    timeout_seconds: int | None = None,
    custom_findings: str | None = None,
) -> None:
    """Registers the MCP server with a CLI agent (claude / agy), launches the
    agent headless and waits for it to finish. Same role as classify_via_ollama /
    classify_via_gemini: the orchestrator calls it the same way regardless of the
    provider, and the output schema does not change.

        agent: "claude" (Claude Code) or "antigravity" (Antigravity/agy CLI)
    """
    log_dir = str(Path(log_dir).expanduser().resolve())
    fw_root = str(Path(fw_root).expanduser().resolve())
    out_path = str(Path(out_path).expanduser().resolve())
    if custom_findings:
        cf = Path(custom_findings).expanduser().resolve()
        custom_findings = str(cf) if cf.exists() else None
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    timeout_seconds = int(timeout_seconds or AGENT_TIMEOUT_SECONDS)

    if not MCP_SERVER_PATH.exists():
        raise RuntimeError(f"MCP server not found: {MCP_SERVER_PATH}")

    # The MCP agent gets its findings in ONE context per run. On real firmware
    # EMBA can produce hundreds/1000+ findings and a single agent turn times out.
    # Fix: split the findings into windows and run the agent once per window
    # (each server instance exposes only findings[offset:offset+limit] and every
    # run appends to the same verdicts.json). This mirrors how local/gemini walk
    # the findings one at a time, just in chunks.
    n_findings = _estimate_finding_count(Path(log_dir), custom_findings)
    batch_size = max(1, int(os.environ.get("LAVA_MCP_BATCH_SIZE", "40")))
    batching_disabled = os.environ.get("LAVA_MCP_NO_BATCH") == "1"
    use_batching = (not batching_disabled) and n_findings > batch_size

    if not use_batching:
        if n_findings > MCP_MAX_FINDINGS and os.environ.get("LAVA_MCP_FORCE") != "1":
            raise RuntimeError(
                f"This scan has ~{n_findings} findings and MCP batching is disabled "
                f"(LAVA_MCP_NO_BATCH=1). One agent turn reliably times out above "
                f"~{MCP_MAX_FINDINGS}. Remove LAVA_MCP_NO_BATCH to batch it, use "
                f"AI_PROVIDER=local / gemini, or set LAVA_MCP_FORCE=1 to try anyway."
            )
        if n_findings > 60:
            print(f"[!] NOTE: ~{n_findings} findings in a single agent turn - may be slow "
                  "or flaky. Unset LAVA_MCP_NO_BATCH to process them in batches.")
        windows = [(0, 0)]  # (offset, limit); limit 0 = whole set
    else:
        offs = list(range(0, n_findings, batch_size))
        # last window uses limit 0 (= "to the end") so a small drift between the
        # estimate and the server's real registry size can't drop findings.
        windows = [(off, batch_size) for off in offs[:-1]] + [(offs[-1], 0)]
        print(f"[+] MCP batching: ~{n_findings} findings -> {len(windows)} batches of "
              f"<= {batch_size} (LAVA_MCP_BATCH_SIZE to resize, LAVA_MCP_NO_BATCH=1 to disable).")

    prompt = _build_agent_prompt(ground_truth_path)

    tmpdir = tempfile.mkdtemp(prefix="lava_mcp_")
    post_cmds: list[list[str]] = []  # so `finally` can always reach it
    result = None
    try:
        # The agent can drop temporary analysis files into its working directory
        # ('workspace'); we run it in this isolated folder so it does not litter
        # the LAVA repo root.
        agent_cwd = os.path.join(tmpdir, "workspace")
        os.makedirs(agent_cwd, exist_ok=True)

        # Resolve the CLI and run the (slow) auth preflight ONCE, up front.
        probe_config = os.path.join(tmpdir, "probe_config.json")
        Path(probe_config).write_text(
            json.dumps(_mcp_config_dict(log_dir, fw_root, out_path, custom_findings), indent=2),
            encoding="utf-8",
        )
        probe_cmd, _, _, _ = _build_agent_command(agent, prompt, probe_config)
        exe = probe_cmd[0]
        cli_name = Path(exe).name
        if not ((os.path.isabs(exe) and os.path.isfile(exe)) or shutil.which(exe)):
            raise RuntimeError(
                f"'{cli_name}' CLI not found (on PATH or in common install locations). "
                f"For MCP mode, install it and log in once (see the README - 'MCP Agent mode'). "
                f"Note: EMBA needs root, but the LAVA AI analysis does NOT run as root - "
                f"the claude/agy install and login are per-user."
            )

        print(f"\n[+] Using AI Provider: MCP agent ({agent})")
        print(f"    MCP server : {MCP_SERVER_PATH}")
        print(f"    log-dir    : {log_dir}")
        print(f"    fw-root    : {fw_root}")
        print(f"    verdicts   : {out_path}")

        _auth_preflight(agent, exe, cli_name, agent_cwd)

        for i, (w_off, w_lim) in enumerate(windows, start=1):
            if use_batching:
                hi = (w_off + w_lim) if w_lim else n_findings
                print(f"\n[+] MCP batch {i}/{len(windows)} - findings "
                      f"{w_off + 1}-{hi} of ~{n_findings}")

            mcp_config_path = os.path.join(tmpdir, f"mcp_config_{i}.json")
            Path(mcp_config_path).write_text(
                json.dumps(_mcp_config_dict(log_dir, fw_root, out_path, custom_findings,
                                            findings_offset=w_off, findings_limit=w_lim),
                           indent=2),
                encoding="utf-8",
            )
            cmd, stdin_text, pre_cmds, post = _build_agent_command(agent, prompt, mcp_config_path)
            post_cmds = post

            for pc in pre_cmds:
                subprocess.run(pc, cwd=agent_cwd, capture_output=True, text=True,
                               timeout=120, check=False)
            try:
                result = subprocess.run(
                    cmd, cwd=agent_cwd, input=stdin_text, capture_output=True, text=True,
                    timeout=timeout_seconds,
                )
            except subprocess.TimeoutExpired as e:
                where = f" on batch {i}/{len(windows)}" if use_batching else ""
                hint = ("lower LAVA_MCP_BATCH_SIZE, or " if use_batching else "")
                raise RuntimeError(
                    f"The agent did not finish{where} within {timeout_seconds}s and was "
                    f"terminated ({hint}raise AGENT_TIMEOUT_SECONDS in ai_config.env / the "
                    f"LAVA_AGENT_TIMEOUT_SECONDS env var)."
                ) from e
            finally:
                for pc in post:
                    subprocess.run(pc, capture_output=True, text=True, timeout=120, check=False)

            if result.returncode != 0:
                blob = (result.stderr or "") + (result.stdout or "")
                _raise_if_auth_error(blob, cli_name)
                where = f" on batch {i}/{len(windows)}" if use_batching else ""
                tail = (result.stderr or result.stdout or "").strip()[-1500:]
                raise RuntimeError(f"The agent run failed{where} (exit {result.returncode}):\n{tail}")

        try:
            count = _validate_verdicts_schema(out_path)
        except RuntimeError as e:
            # The agent returned exit 0 but wrote no verdicts - show what it said.
            out_tail = (result.stdout or "").strip()[-2000:] if result else ""
            err_tail = (result.stderr or "").strip()[-800:] if result else ""
            raise RuntimeError(
                f"{e}\n--- agent ({agent}) stdout ---\n{out_tail}\n"
                f"--- agent stderr ---\n{err_tail}"
            ) from e
        if use_batching and count < n_findings:
            print(f"[!] NOTE: {count} verdicts for ~{n_findings} findings - some batches "
                  "may have left findings unclassified.")
        print(f"[OK] The MCP agent wrote {count} verdicts -> {out_path}")
    finally:
        for pc in post_cmds:
            subprocess.run(pc, capture_output=True, text=True, timeout=120, check=False)
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Evaluation (for test mode)
# ---------------------------------------------------------------------------
def compute_metrics(results: list[dict]) -> dict:
    """Computes precision/recall/F1/accuracy treating the TP class as positive."""
    tp = fp = tn = fn = errors = 0
    for r in results:
        pred, true = r["predicted_verdict"], r["true_verdict"]
        if pred == "ERROR":
            errors += 1
            continue
        if true == "TP" and pred == "TP":
            tp += 1
        elif true == "FP" and pred == "FP":
            tn += 1
        elif true == "FP" and pred == "TP":
            fp += 1
        elif true == "TP" and pred == "FP":
            fn += 1

    total_scored = tp + tn + fp + fn
    accuracy = (tp + tn) / total_scored if total_scored else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn, "errors": errors,
        "accuracy": round(accuracy, 3),
        "precision_TP": round(precision, 3),
        "recall_TP": round(recall, 3),
        "f1_TP": round(f1, 3),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run_test_mode(args, config: dict):
    data = json.loads(Path(args.ground_truth).read_text(encoding="utf-8"))
    few_shot = data["few_shot"]
    test_set = data["test_set"]

    system_prompt = build_system_prompt(few_shot)
    base_url = f"http://{config['LOCAL_AI_IP']}:{config['LOCAL_AI_PORT']}"
    max_chars = int(config.get("AI_MAX_CHARS_TO_ANALYSE", 5000))

    results = []
    for i, item in enumerate(test_set, start=1):
        print(f"[{i}/{len(test_set)}] evaluating {item['finding_id']} ({item['file_path']})...")
        pred = classify_item(item, config, system_prompt, max_chars)
        results.append({
            "finding_id": item["finding_id"],
            "file_path": item["file_path"],
            "true_verdict": item["verdict"],
            "predicted_verdict": pred["verdict"],
            "confidence": pred.get("confidence"),
            "model_reasoning": pred.get("reasoning"),
            "human_reasoning": item.get("reasoning"),
            "attempts": pred.get("attempts"),
        })
        match = "OK" if pred["verdict"] == item["verdict"] else "MISS"
        print(f"    true={item['verdict']}  model={pred['verdict']}  {match}")

        # Intermediate save on every iteration (metrics excluded)
        output = {"results": results, "metrics": {}}
        atomic_save(output, args.out)

    metrics = compute_metrics(results)
    output = {"results": results, "metrics": metrics}
    atomic_save(output, args.out)

    print("\n=== RESULTS ===")
    for k, v in metrics.items():
        print(f"  {k}: {v}")
    print(f"\n[+] Detailed results: {args.out}")


def run_full_mode(args, config: dict):
    data = json.loads(Path(args.ground_truth).read_text(encoding="utf-8")) if args.ground_truth else None
    few_shot = data["few_shot"] if data else []
    if not few_shot:
        print("[!] WARNING: no few-shot examples given (--ground-truth not set); the prompt will be weaker.")

    findings = json.loads(Path(args.enriched).read_text(encoding="utf-8"))
    system_prompt = build_system_prompt(few_shot)
    base_url = f"http://{config['LOCAL_AI_IP']}:{config['LOCAL_AI_PORT']}"
    max_chars = int(config.get("AI_MAX_CHARS_TO_ANALYSE", 5000))

    results = []
    for i, item in enumerate(findings, start=1):
        label = item.get("file_path", "?")
        print(f"[{i}/{len(findings)}] evaluating {label}...")
        pred = classify_item(item, config, system_prompt, max_chars)
        modules = item.get("found_by_modules") or ([item["module"]] if item.get("module") else [])
        results.append({
            "file_path": item.get("file_path"),
            "matched_content": item.get("matched_content"),
            "found_by_modules": modules,
            "corroboration_count": item.get("corroboration_count"),
            "source": item.get("source") or _derive_source(modules),
            "line_no": item.get("line_no") or (item.get("extra") or {}).get("line_no"),
            "predicted_verdict": pred["verdict"],
            "confidence": pred.get("confidence"),
            "model_reasoning": pred.get("reasoning"),
            "attempts": pred.get("attempts"),
        })

        # Save results on every step (to survive Ctrl+C interruptions)
        atomic_save(results, args.out)

    from collections import Counter
    dist = Counter(r["predicted_verdict"] for r in results)

    # Always create the file (even with 0 findings)
    atomic_save(results, args.out)

    print("\n=== SUMMARY ===")
    for k, v in dist.items():
        print(f"  {k}: {v}")
    print(f"\n[+] Results: {args.out}")


def main():
    ap = argparse.ArgumentParser(description="LAVA - classifies EMBA findings as TP/FP with an AI provider.")
    ap.add_argument("--mode", choices=["test", "run"], required=True)
    ap.add_argument("--config", required=True, help="config/ai_config.env file")
    ap.add_argument("--ground-truth", help="required in test mode; optional in run mode (few-shot only)")
    ap.add_argument("--enriched", help="required in run mode - the enricher.py output")
    ap.add_argument("--out", required=True)
    ap.add_argument("--log-dir", help="EMBA log directory (used only in MCP provider mode)")
    ap.add_argument("--fw-root", help="firmware extraction root (MCP mode; defaults to --log-dir)")
    ap.add_argument("--custom-findings", help="custom_scan.py output; in MCP mode the agent verdicts these too")
    args = ap.parse_args()

    config = load_ai_config(Path(args.config))
    provider = (config.get("AI_PROVIDER") or "local").strip().lower()

    # --- MCP (agentic) provider mode -----------------------------------
    # AI_PROVIDER = mcp_claude | mcp_antigravity | mcp
    # A third provider branch that never touches the local/Gemini branches.
    if provider.startswith("mcp"):
        agent = {
            "mcp_claude": "claude",
            "mcp_antigravity": "antigravity",
            "mcp": "claude",
        }.get(provider, "claude")

        log_dir = args.log_dir
        if not log_dir and args.enriched:
            # run_lava.sh: --out <LogDir>/lava_out/<ts>/verdicts.json
            log_dir = str(Path(args.out).resolve().parents[2])
        if not log_dir:
            ap.error("--log-dir is required for MCP provider mode")
        fw_root = args.fw_root or log_dir

        if args.mode != "run":
            ap.error("MCP provider mode only works with --mode run")

        try:
            _to = int(config.get("AGENT_TIMEOUT_SECONDS") or 0) or None
        except (TypeError, ValueError):
            _to = None
        classify_via_mcp_agent(
            log_dir=log_dir,
            fw_root=fw_root,
            out_path=args.out,
            agent=agent,
            ground_truth_path=args.ground_truth,
            timeout_seconds=_to,
            custom_findings=args.custom_findings,
        )
        return

    if not config["LOCAL_AI_MODEL"]:
        print("[!] WARNING: LOCAL_AI_MODEL is empty in the config - there is no identify_ai_model logic here, make sure you set the correct model in the config.")

    if args.mode == "test":
        if not args.ground_truth:
            ap.error("--ground-truth is required for --mode test")
        run_test_mode(args, config)
    else:
        if not args.enriched:
            ap.error("--enriched is required for --mode run")
        run_full_mode(args, config)


if __name__ == "__main__":
    main()
