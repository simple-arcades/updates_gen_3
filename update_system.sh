#!/bin/bash
# Simple Arcades - System Updater (Customer Facing)
# SCRIPT_BUILD=2026-01-13-v5.1 (fix perms: ignore tar modes for new files + apply FILE_PERMISSIONS overrides)
# Design goals:
# - Customer-safe: copy first, delete second, abort on failures
# - Self-updating updater (optional)
# - Level B permissions:
#     * If target already exists, preserve owner/group/mode
#     * If target is new, inherit owner/group from nearest existing parent dir
#     * Explicit FILE_PERMISSIONS overrides always win
# - Optional baseline DIR_PERMISSIONS (non-recursive) to prevent drift on key roots

# Must run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root."
  exit 1
fi

# ----------------------------
# Config
# ----------------------------
# Base URLs (primary + optional mirrors)
# Primary should be your main update host. Mirrors are optional; leave blank to disable.
PRIMARY_BASE_URL="https://raw.githubusercontent.com/simple-arcades/updates_gen_3/main"
MIRROR1_BASE_URL=""  # e.g. https://raw.githubusercontent.com/simple-arcades/updates_gen_3/main
MIRROR2_BASE_URL=""
MIRROR3_BASE_URL=""

# Backward-compatible: existing code paths use UPDATE_BASE_URL
UPDATE_BASE_URL="$PRIMARY_BASE_URL"

# Optional Basic Auth for hosts that require it (self-host). Not used for GitHub by default.
AUTH_FILE="/home/pi/RetroPie/custom_scripts/.sa_updater_auth"
AUTH_REQUIRED_HOSTS=()

# Download progress UI (shown for large downloads only)
PROGRESS_MIN_BYTES=$((5*1024*1024))

# Internal (set by downloader)
BASE_URLS_BUILT=0
LAST_DOWNLOAD_BASE=""
LAST_DOWNLOAD_URL=""
LAST_DOWNLOAD_ERROR=""
SA_USER=""
SA_PASS=""
LOCAL_VERSION_FILE="/home/pi/RetroPie/custom_scripts/logs/update_version.log"
LOG_FILE="/home/pi/RetroPie/custom_scripts/logs/update_system.log"
HASH_LOG="/home/pi/RetroPie/custom_scripts/logs/update_hashes.log"
XML_FILE="/etc/emulationstation/themes/Retro Console (Default)/style/snes_usa.xml"

TEMP_UPDATE_DIR="/tmp/update_package_$$"
META_DIR_NAME=".sa_meta"

SELF_UPDATE_ENABLED=1
SELF_UPDATE_URL="$UPDATE_BASE_URL/update_system.sh"

# Checksums: requires publishing matching *.sha256 files
CHECKSUM_VERIFY_ENABLED=1

# Network timeouts / retries (wifi can be flaky)
WGET_TIMEOUT=20
WGET_TRIES=3

APT_UPDATED=0
LOCKFILE="/var/run/update_system.lock"

# ----------------------------
# Baseline directory permissions (non-recursive)
# These are *top-level* corrections only; Level B handles everything else.
# ----------------------------
declare -A DIR_PERMISSIONS=(
  ["/home/pi/RetroPie"]="pi:pi 755"
  ["/home/pi/pixelcade"]="pi:pi 755"
  ["/home/pi/screenshots"]="pi:pi 755"
  ["/home/pi/music_settings"]="pi:pi 755"
  ["/opt/retropie/configs"]="pi:pi 755"
  ["/opt/retropie/supplementary"]="root:root 755"
  ["/opt/retropie/libretrocores"]="root:root 755"
  ["/etc/emulationstation"]="root:root 755"
  ["/boot"]="root:root 755"
)

# Explicit file overrides ONLY when needed (read-only, special ownership, etc.)
# Example:
#   ["/home/pi/RetroPie/roms/atomiswave/file.bin"]="root:root 444"
declare -A FILE_PERMISSIONS=(
  ["/home/pi/RetroPie/custom_scripts/logs/update_version.log"]="pi:pi 644"
  ["/home/pi/RetroPie/custom_scripts/logs/update_system.log"]="pi:pi 644"
  ["/home/pi/RetroPie/custom_scripts/.sa_updater_auth"]="root:root 600"
  ["/home/pi/RetroPie/roms/savestates/savefiles/reicast/mslug6.zip.nvmem"]="pi:pi 444"
  ["/home/pi/RetroPie/roms/savestates/savefiles/reicast/mslug6.zip.nvmem2"]="pi:pi 444"
)

# ----------------------------
# Helpers
# ----------------------------
log_update() {
  local msg="$1"
  mkdir -p "$(dirname "$LOG_FILE")" >/dev/null 2>&1
  if touch "$LOG_FILE" >/dev/null 2>&1; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $msg" >> "$LOG_FILE"
  else
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $msg" >> /tmp/update_system.log
  fi
}

show_message() {
  local message="$1"
  if command -v dialog >/dev/null 2>&1; then
    dialog --ok-button "OK" --msgbox "$message" 12 70
  else
    echo "$message"
  fi
}

# ----------------------------
# Downloader helpers (mirrors + auth + progress)
# ----------------------------
normalize_base_url() {
  local u="$1"
  # Trim trailing slashes
  while [[ "$u" == */ ]]; do u="${u%/}"; done
  echo "$u"
}

build_base_urls() {
  [ "${BASE_URLS_BUILT:-0}" -eq 1 ] && return 0

  PRIMARY_BASE_URL="$(normalize_base_url "$PRIMARY_BASE_URL")"
  UPDATE_BASE_URL="$PRIMARY_BASE_URL"
  MIRROR1_BASE_URL="$(normalize_base_url "$MIRROR1_BASE_URL")"
  MIRROR2_BASE_URL="$(normalize_base_url "$MIRROR2_BASE_URL")"
  MIRROR3_BASE_URL="$(normalize_base_url "$MIRROR3_BASE_URL")"

  BASE_URLS=()
  [ -n "$PRIMARY_BASE_URL" ] && BASE_URLS+=("$PRIMARY_BASE_URL")
  [ -n "$MIRROR1_BASE_URL" ] && BASE_URLS+=("$MIRROR1_BASE_URL")
  [ -n "$MIRROR2_BASE_URL" ] && BASE_URLS+=("$MIRROR2_BASE_URL")
  [ -n "$MIRROR3_BASE_URL" ] && BASE_URLS+=("$MIRROR3_BASE_URL")

  BASE_URLS_BUILT=1
}

url_host() {
  # Extract host from http(s)://host[:port]/...
  local u="$1"
  echo "$u" | awk -F/ '{print $3}' | cut -d: -f1
}

load_auth() {
  SA_USER=""
  SA_PASS=""

  if [ -f "$AUTH_FILE" ]; then
    # Ensure file is root-only to avoid privilege escalation
    local owner group perm
    owner="$(stat -c '%U' "$AUTH_FILE" 2>/dev/null)"
    group="$(stat -c '%G' "$AUTH_FILE" 2>/dev/null)"
    perm="$(stat -c '%a' "$AUTH_FILE" 2>/dev/null)"
    if [ "$owner" != "root" ] || [ "$group" != "root" ] || [ "$perm" != "600" ]; then
      # Don't auto-fix here; the script will fix declared permissions elsewhere.
      log_update "Warning: AUTH_FILE permissions not strict (expected root:root 600)."
    fi

    # shellcheck disable=SC1090
    . "$AUTH_FILE" >/dev/null 2>&1 || true
  fi
}

host_requires_auth() {
  local h="$1"
  local x
  for x in "${AUTH_REQUIRED_HOSTS[@]}"; do
    [ "$h" = "$x" ] && return 0
  done
  return 1
}

human_bytes() {
  local bytes="$1"
  if ! [[ "$bytes" =~ ^[0-9]+$ ]]; then
    echo "?"
    return
  fi
  local kib=1024
  local mib=$((1024*1024))
  local gib=$((1024*1024*1024))
  if [ "$bytes" -ge "$gib" ]; then
    awk -v b="$bytes" 'BEGIN{printf "%.1f GB", b/1024/1024/1024}'
  elif [ "$bytes" -ge "$mib" ]; then
    awk -v b="$bytes" 'BEGIN{printf "%.1f MB", b/1024/1024}'
  elif [ "$bytes" -ge "$kib" ]; then
    awk -v b="$bytes" 'BEGIN{printf "%.1f KB", b/1024}'
  else
    echo "${bytes} B"
  fi
}

ensure_file_exists() {
  local file_path="$1"
  local default_value="$2"
  if [ ! -f "$file_path" ]; then
    mkdir -p "$(dirname "$file_path")" >/dev/null 2>&1
    : > "$file_path"
    echo "$default_value" > "$file_path"
    log_update "Initialized $file_path with value: $default_value"
  fi
}

ensure_hash_log() {
  mkdir -p "$(dirname "$HASH_LOG")" >/dev/null 2>&1
  if [ ! -f "$HASH_LOG" ]; then
    : > "$HASH_LOG" 2>/dev/null
  fi
  chown pi:pi "$HASH_LOG" >/dev/null 2>&1
  chmod 644 "$HASH_LOG" >/dev/null 2>&1
}

get_saved_hash() {
  local fn="$1"
  [ -f "$HASH_LOG" ] || return 1
  awk -v f="$fn" '$1==f {print $2; exit}' "$HASH_LOG" 2>/dev/null
}

set_saved_hash() {
  local fn="$1"
  local h="$2"
  [ -z "$fn" ] && return 1
  [ -z "$h" ] && return 1

  mkdir -p "$(dirname "$HASH_LOG")" >/dev/null 2>&1
  touch "$HASH_LOG" >/dev/null 2>&1

  local tmp="/tmp/update_hashes_$$.tmp"
  awk -v f="$fn" '$1!=f' "$HASH_LOG" 2>/dev/null > "$tmp"
  printf "%s %s\n" "$fn" "$h" >> "$tmp"
  mv -f "$tmp" "$HASH_LOG" >/dev/null 2>&1

  chown pi:pi "$HASH_LOG" >/dev/null 2>&1
  chmod 644 "$HASH_LOG" >/dev/null 2>&1
}

parse_sha256_file_first_hash() {
  local sha_file="$1"
  [ -f "$sha_file" ] || return 1
  awk 'NF>=1 {print $1; exit}' "$sha_file" 2>/dev/null
}

get_remote_hash() {
  # Downloads <filename>.sha256 and returns the hash (first field)
  local filename="$1"
  local sha_url="$UPDATE_BASE_URL/$filename.sha256"
  local sha_path="/tmp/$filename.sha256"

  rm -f "$sha_path" >/dev/null 2>&1
  if ! download_file "$sha_url" "$sha_path"; then
    return 1
  fi

  parse_sha256_file_first_hash "$sha_path"
}

clean_version_name() {
  local v="$1"
  v="${v##*/}"
  v="${v%.tar.gz}"
  echo "$v"
}

apply_dir_baselines() {
  # Deprecated: moved to per-update .sa_meta/permissions.txt rules.
  return 0
}

apply_file_permission_overrides() {
  # Deprecated: moved to per-update .sa_meta/permissions.txt rules.
  return 0
}

# ----------------------------
# Optional per-update permission rules (.sa_meta/permissions.txt)
# ----------------------------
# Applied AFTER copy/delete and AFTER Level-B perm restoration.
#
# Format (pipe-delimited; paths may contain spaces):
#   DIR|/abs/path|owner:group|755
#   DIRR|/abs/path|owner:group|755      # recursive: dirs get 755, files get 644 (derived), scripts get 755
#   FILE|/abs/path|owner:group|444
#
# Notes:
# - DIR affects the directory only (non-recursive)
# - DIRR treats the mode as the directory mode; files under it get a derived mode (dir_mode & 666)
# - FILE applies the exact mode to a single file

is_safe_perm_target() {
  local p="$1"
  [ -n "$p" ] || return 1
  case "$p" in
    /*) ;;
    *) return 1 ;;
  esac
  case "$p" in
    *..*|*'\'* ) return 1 ;;
  esac
  # disallow obviously dangerous roots
  case "$p" in
    /|/proc/*|/sys/*|/dev/*|/run/*|/tmp/*) return 1 ;;
  esac
  # allowlist common SA update roots
  case "$p" in
    /home/pi/*|/opt/retropie/*|/usr/local/*|/etc/*|/boot/*) return 0 ;;
    *) return 1 ;;
  esac
}

apply_permissions_rules_file() {
  local rules="$1"
  [ -f "$rules" ] || return 0

  local line typ path og mode

  apply_one_dir() {
    local p="$1" og="$2" dmode="$3"
    [ -d "$p" ] || { log_update "WARN: DIR path not found: $p"; return 0; }
    chown "$og" "$p" >/dev/null 2>&1 || true
    chmod "$dmode" "$p" >/dev/null 2>&1 || true
  }

  apply_one_file() {
    local p="$1" og="$2" fmode="$3"
    [ -e "$p" ] || { log_update "WARN: FILE path not found: $p"; return 0; }
    chown "$og" "$p" >/dev/null 2>&1 || true
    chmod "$fmode" "$p" >/dev/null 2>&1 || true
  }

  apply_one_dirr() {
    local p="$1" og="$2" dmode="$3" pmode fmode
    [ -d "$p" ] || { log_update "WARN: DIRR path not found: $p"; return 0; }

    # dirs use dmode; files get derived fmode
    pmode="$dmode"
    fmode="$(printf '%o' $((8#$pmode & 8#666)))"

    chown -R "$og" "$p" >/dev/null 2>&1 || true
    find "$p" -type d -exec chmod "$dmode" {} + >/dev/null 2>&1 || true
    find "$p" -type f -exec chmod "$fmode" {} + >/dev/null 2>&1 || true
    # scripts/menu launchers executable
    find "$p" -type f \( -name '*.sh' -o -name '*.rp' \) -exec chmod 755 {} + >/dev/null 2>&1 || true
  }

  # 3-pass order: DIR, then DIRR, then FILE
  for pass in DIR DIRR FILE; do
    while IFS= read -r line || [ -n "$line" ]; do
      # trim CR
      line="${line%
}"
      # skip empty/comments
      case "$line" in
        ''|\#*) continue ;;
      esac

      IFS='|' read -r typ path og mode _extra <<< "$line"
      [ "$typ" = "$pass" ] || continue

      # basic validation
      [ -n "$path" ] || { log_update "WARN: bad permissions line: $line"; continue; }
      is_safe_perm_target "$path" || { log_update "WARN: unsafe perm path skipped: $path"; continue; }
      case "$og" in
        *:*) ;;
        *) log_update "WARN: bad owner:group skipped: $line"; continue ;;
      esac
      case "$mode" in
        [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
        *) log_update "WARN: bad mode skipped: $line"; continue ;;
      esac

      case "$typ" in
        DIR)  apply_one_dir  "$path" "$og" "$mode" ;;
        DIRR) apply_one_dirr "$path" "$og" "$mode" ;;
        FILE) apply_one_file "$path" "$og" "$mode" ;;
      esac
    done < "$rules"
  done
}

apply_permissions_from_meta() {
  local update_root="$1"
  local rules_path
  rules_path="$(control_file_path "$update_root" 'permissions.txt' 2>/dev/null || true)"
  if [ -n "$rules_path" ] && [ -f "$rules_path" ]; then
    log_update "Applying permissions rules: $rules_path"
    apply_permissions_rules_file "$rules_path"
  fi
}


download_file() {
  local url="$1"
  local out_path="$2"

  LAST_DOWNLOAD_BASE=""
  LAST_DOWNLOAD_URL=""
  LAST_DOWNLOAD_ERROR=""

  # Prefer curl (supports HTTPS + Basic Auth cleanly)
  if ! command -v curl >/dev/null 2>&1; then
    LAST_DOWNLOAD_ERROR="Missing dependency: curl is not installed."
    log_update "$LAST_DOWNLOAD_ERROR"
    return 1
  fi

  build_base_urls
  load_auth

  # Determine relative path if URL is built from primary base
  local rel=""
  if [[ "$url" == "$UPDATE_BASE_URL/"* ]]; then
    rel="${url#"$UPDATE_BASE_URL/"}"
  fi

  local candidates=()
  if [ -n "$rel" ]; then
    local base
    for base in "${BASE_URLS[@]}"; do
      [ -n "$base" ] && candidates+=("$base/$rel")
    done
  else
    candidates+=("$url")
  fi

  local last_rc=0
  local last_err=""

  for cand in "${candidates[@]}"; do
    local base_used=""
    if [ -n "$rel" ]; then
      base_used="${cand%/$rel}"
    else
      base_used="$(echo "$cand" | awk -F/ '{print $1"//"$3}')"
    fi

    local host
    host="$(url_host "$cand")"

    local auth_args=()
    if host_requires_auth "$host"; then
      if [ -z "${SA_USER:-}" ] || [ -z "${SA_PASS:-}" ]; then
        last_err="Auth required for $host but credentials missing (AUTH_FILE)."
        last_rc=22
        continue
      fi
      auth_args=(--user "$SA_USER:$SA_PASS")
    fi

    local tmp_path="${out_path}.part"
    local errfile="/tmp/sa_curl_err_${$}.txt"
    rm -f "$tmp_path" "$errfile" >/dev/null 2>&1

    # Probe size (best effort)
    local total=""
    total="$(curl -fsSIL "${auth_args[@]}" --connect-timeout "$WGET_TIMEOUT" --max-time "$((WGET_TIMEOUT*5))" "$cand" 2>/dev/null | awk -F': ' 'tolower($1)=="content-length"{print $2}' | tr -d '
' | tail -n 1)"

    local use_gauge=0
    if command -v dialog >/dev/null 2>&1 && [ -n "${TERM:-}" ] && [[ "$total" =~ ^[0-9]+$ ]] && [ "$total" -ge "${PROGRESS_MIN_BYTES:-0}" ]; then
      use_gauge=1
    fi

    if [ "$use_gauge" -eq 1 ]; then
      # Download in background and show progress gauge by polling file size
      (
        curl -fsSL "${auth_args[@]}" --connect-timeout "$WGET_TIMEOUT" --max-time "$((WGET_TIMEOUT*120))" \
          --retry "$WGET_TRIES" --retry-delay 2 --retry-connrefused \
          "$cand" -o "$tmp_path" 2>"$errfile" &
        pid=$!

        while kill -0 "$pid" >/dev/null 2>&1; do
          downloaded=$(stat -c%s "$tmp_path" 2>/dev/null || echo 0)
          if [[ "$downloaded" =~ ^[0-9]+$ ]] && [ "$downloaded" -ge 0 ]; then
            pct=$(( downloaded * 100 / total ))
            [ "$pct" -gt 99 ] && pct=99
          else
            pct=0
          fi

          echo "$pct"
          echo "XXX"
          echo "Downloading: $(basename "$cand")
$(human_bytes "$downloaded") of $(human_bytes "$total")"
          echo "XXX"
          sleep 0.5
        done

        wait "$pid"
        rc=$?

        # Finalize gauge
        downloaded=$(stat -c%s "$tmp_path" 2>/dev/null || echo 0)
        if [ "$rc" -eq 0 ]; then
          echo "100"
          echo "XXX"
          echo "Download complete: $(basename "$cand")
$(human_bytes "$downloaded")"
          echo "XXX"
          sleep 0.7
        fi

        exit "$rc"
      ) | dialog --title "Downloading Update" --gauge "Starting download...
$(basename "$cand")
Size: $(human_bytes "$total")" 12 70 0
      rc=$?
    else
      # Quiet download
      curl -fsSL "${auth_args[@]}" --connect-timeout "$WGET_TIMEOUT" --max-time "$((WGET_TIMEOUT*120))" \
        --retry "$WGET_TRIES" --retry-delay 2 --retry-connrefused \
        "$cand" -o "$tmp_path" 2>"$errfile"
      rc=$?
    fi

    if [ "$rc" -eq 0 ] && [ -s "$tmp_path" ]; then
      mv -f "$tmp_path" "$out_path" >/dev/null 2>&1
      LAST_DOWNLOAD_BASE="$base_used"
      LAST_DOWNLOAD_URL="$cand"
      LAST_DOWNLOAD_ERROR=""
      rm -f "$errfile" >/dev/null 2>&1
      return 0
    fi

    last_rc=$rc
    if [ -f "$errfile" ]; then
      last_err="$(tail -n 1 "$errfile" | tr -d '
')"
    else
      last_err="curl failed (rc=$rc)"
    fi

    # Clean partial
    rm -f "$tmp_path" "$errfile" >/dev/null 2>&1
  done

  # Summarize failure
  case "$last_rc" in
    6) LAST_DOWNLOAD_ERROR="DNS lookup failed (no internet or DNS).";;
    7) LAST_DOWNLOAD_ERROR="Connection failed (server down or blocked).";;
    22) LAST_DOWNLOAD_ERROR="Server rejected the request (auth/404/HTTP error).";;
    28) LAST_DOWNLOAD_ERROR="Connection timed out.";;
    *) LAST_DOWNLOAD_ERROR="Download failed.";;
  esac

  if [ -n "$last_err" ]; then
    LAST_DOWNLOAD_ERROR="$LAST_DOWNLOAD_ERROR
Details: $last_err"
  fi

  log_update "Download failed: $url"
  log_update "$LAST_DOWNLOAD_ERROR"
  rm -f "$out_path" >/dev/null 2>&1
  return 1
}


is_valid_update_filename() {
  local f="$1"
  [[ "$f" =~ ^[A-Za-z0-9._-]+\.tar\.gz$ ]]
}

validate_tarball_safe() {
  # Reject absolute paths, any ".." traversal, and Windows-style backslashes inside tarball
  local archive="$1"
  local listing rc entry

  # Capture tar output so we can log meaningful errors
  listing="$(tar -tzf "$archive" 2>&1)"
  rc=$?
  if [ $rc -ne 0 ]; then
    # Collapse newlines for log readability
    local one_line
    one_line="$(echo "$listing" | tr '
' ' ' | sed 's/[[:space:]]\+/ /g')"
    log_update "Tar list failed (rc=$rc) for $(basename "$archive"): $one_line"
    return 1
  fi

  while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    # Strip any stray CR just in case
    entry="${entry%$'
'}"

    [[ "$entry" == /* ]] && { log_update "Unsafe tar entry (absolute path): $entry"; return 1; }
    [[ "$entry" =~ (^|/)\.\.($|/) ]] && { log_update "Unsafe tar entry (path traversal): $entry"; return 1; }
    [[ "$entry" == *\\* ]] && { log_update "Unsafe tar entry (backslash): $entry"; return 1; }
  done <<< "$listing"

  return 0
}

verify_checksum_for_download() {
  local filename="$1"   # e.g. 11.1.9.tar.gz or update_system.sh
  local tmpdir="$2"     # e.g. /tmp

  [ "$CHECKSUM_VERIFY_ENABLED" -ne 1 ] && return 0

  local base_url="${3:-${LAST_DOWNLOAD_BASE:-$UPDATE_BASE_URL}}"
  local checksum_url="$base_url/$filename.sha256"
  local checksum_path="$tmpdir/$filename.sha256"

  log_update "Downloading checksum: $checksum_url"
  if ! download_file "$checksum_url" "$checksum_path"; then
    log_update "Checksum download failed for $filename"
    show_message "Failed to download checksum for:\n\n$filename\n\nUpdate aborted."
    return 1
  fi

  local oldpwd="$PWD"
  cd "$tmpdir" >/dev/null 2>&1
  sha256sum -c "$checksum_path" >/dev/null 2>&1
  local rc=$?
  cd "$oldpwd" >/dev/null 2>&1

  if [ $rc -ne 0 ]; then
    log_update "Checksum verification FAILED for $filename"
    show_message "Checksum verification failed for:\n\n$filename\n\nUpdate aborted."
    return 1
  fi

  log_update "Checksum verification PASSED for $filename"
  return 0
}

update_version_in_xml() {
  local new_version="$1"
  if [ -f "$XML_FILE" ]; then
    sed -i "s|<text>v.*</text>|<text>v$new_version</text>|" "$XML_FILE" >/dev/null 2>&1
    log_update "Updated version text in $XML_FILE to v$new_version"
  else
    log_update "XML file not found: $XML_FILE"
  fi
}

# ----------------------------
# Control files in update pack
# ----------------------------
control_file_path() {
  local root="$1"
  local name="$2"
  local meta="$root/$META_DIR_NAME/$name"
  local legacy="$root/$name"

  if [ -f "$meta" ]; then
    echo "$meta"; return 0
  fi
  if [ -f "$legacy" ]; then
    echo "$legacy"; return 0
  fi
  return 1
}

strip_control_files() {
  local root="$1"
  rm -f "$root/delete_list.txt" "$root/dependencies.txt" "$root/permissions.txt" >/dev/null 2>&1
  rm -rf "$root/$META_DIR_NAME" >/dev/null 2>&1
}

is_safe_delete_path() {
  local p="$1"
  [[ "$p" == /* ]] || return 1
  [[ "$p" != "/" ]] || return 1
  [[ "$p" =~ (^|/)\.\.($|/) ]] && return 1
  return 0
}

install_update_dependencies() {
  local root="$1"
  local dep_file line
  dep_file="$(control_file_path "$root" "dependencies.txt")" || return 0

  log_update "Found dependencies file ($dep_file). Installing dependencies."

  if ! command -v apt-get >/dev/null 2>&1; then
    log_update "apt-get not found; cannot install dependencies."
    show_message "Dependency install failed: apt-get not found. Update aborted."
    return 1
  fi

  local pkgs=()
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue
    [[ "$line" =~ ^# ]] && continue
    if [[ "$line" == apt:* ]]; then
      line="${line#apt:}"
      line="${line#"${line%%[![:space:]]*}"}"
      line="${line%"${line##*[![:space:]]}"}"
    fi
    if [[ ! "$line" =~ ^[A-Za-z0-9.+-]+$ ]]; then
      log_update "Invalid dependency entry: $line"
      show_message "Invalid dependencies.txt entry:\n\n$line\n\nUpdate aborted."
      return 1
    fi
    pkgs+=("$line")
  done < "$dep_file"

  [ ${#pkgs[@]} -eq 0 ] && return 0

  if [ "${APT_UPDATED:-0}" -ne 1 ]; then
    log_update "Running apt-get update (once per session)."
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1
    if [ $? -ne 0 ]; then
      log_update "apt-get update failed."
      show_message "Failed to update package lists. Update aborted."
      return 1
    fi
    APT_UPDATED=1
  fi

  log_update "Installing dependencies: ${pkgs[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    log_update "apt-get install failed: ${pkgs[*]}"
    show_message "Failed to install update dependencies. Update aborted."
    return 1
  fi

  log_update "Dependencies installed successfully."
  return 0
}

process_delete_list() {
  local root="$1"
  local delete_file target
  delete_file="$(control_file_path "$root" "delete_list.txt")" || return 0

  log_update "Found delete_list.txt in update pack. Processing deletions."
  while IFS= read -r target || [ -n "$target" ]; do
    target="${target#"${target%%[![:space:]]*}"}"
    target="${target%"${target##*[![:space:]]}"}"
    [ -z "$target" ] && continue
    [[ "$target" =~ ^# ]] && continue

    if ! is_safe_delete_path "$target"; then
      log_update "Unsafe delete target rejected: $target"
      show_message "Unsafe delete target rejected:\n\n$target\n\nUpdate aborted."
      return 1
    fi

    log_update "Deleting target: $target"
    rm -rf -- "$target" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
      log_update "Failed to delete: $target"
      show_message "Failed to delete:\n\n$target\n\nUpdate aborted."
      return 1
    fi
  done < "$delete_file"

  log_update "Delete list processed successfully."
  return 0
}

# ----------------------------
# Level B permission engine
# ----------------------------

nearest_parent_og() {
  local p="$1"
  while [ "$p" != "/" ] && [ ! -d "$p" ]; do
    p="$(dirname "$p")"
  done
  if [ -d "$p" ]; then
    stat -c '%u:%g' "$p" 2>/dev/null || echo "0:0"
  else
    echo "0:0"
  fi
}

build_perm_plan() {
  # plan line format:
  # type(T=dir/file)\trelpath\texisted_before(0/1)\told_uidgid\told_mode\tstaged_mode
  local root="$1"
  local plan="$2"
  : > "$plan"

  # Directories first
  find "$root" -type d \
    ! -path "$root/$META_DIR_NAME" \
    ! -path "$root/$META_DIR_NAME/*" \
    | sort | while IFS= read -r d; do
      local rel="${d#$root/}"
      [ -z "$rel" ] && continue
      local target="/$rel"
      local existed=0 oldog="" oldmode=""
      if [ -d "$target" ]; then
        existed=1
        oldog="$(stat -c '%u:%g' "$target" 2>/dev/null)"
        oldmode="$(stat -c '%a' "$target" 2>/dev/null)"
      fi
      local stagedmode
      stagedmode="$(stat -c '%a' "$d" 2>/dev/null)"
      printf "D\t%s\t%d\t%s\t%s\t%s\n" "$rel" "$existed" "$oldog" "$oldmode" "$stagedmode" >> "$plan"
    done

  # Files
  find "$root" -type f \
    ! -path "$root/$META_DIR_NAME/*" \
    ! -name "delete_list.txt" \
    ! -name "dependencies.txt" \
    | sort | while IFS= read -r f; do
      local rel="${f#$root/}"
      [ -z "$rel" ] && continue
      local target="/$rel"
      local existed=0 oldog="" oldmode=""
      if [ -f "$target" ] || [ -L "$target" ]; then
        existed=1
        oldog="$(stat -c '%u:%g' "$target" 2>/dev/null)"
        oldmode="$(stat -c '%a' "$target" 2>/dev/null)"
      fi
      local stagedmode
      stagedmode="$(stat -c '%a' "$f" 2>/dev/null)"
      printf "F\t%s\t%d\t%s\t%s\t%s\n" "$rel" "$existed" "$oldog" "$oldmode" "$stagedmode" >> "$plan"
    done
}

apply_perm_plan() {
  local plan="$1"
  [ -f "$plan" ] || return 0

  local target dparent parentog pmode dmode fmode

  # Directories first
  while IFS=$'	' read -r typ rel existed oldog oldmode stagedmode; do
    [ "$typ" = "D" ] || continue
    target="/$rel"
    [ -e "$target" ] || continue

    if [ "$existed" -eq 1 ] && [ -n "$oldog" ] && [ -n "$oldmode" ]; then
      chown "$oldog" "$target" >/dev/null 2>&1 || true
      chmod "$oldmode" "$target" >/dev/null 2>&1 || true
    else
      dparent="$(dirname "$target")"
      parentog="$(nearest_parent_og "$dparent")"
      chown "$parentog" "$target" >/dev/null 2>&1 || true

      pmode="$(stat -c '%a' "$dparent" 2>/dev/null || true)"
      if [ -n "$pmode" ]; then
        dmode="$pmode"
      else
        dmode="755"
      fi
      chmod "$dmode" "$target" >/dev/null 2>&1 || true
    fi
  done < "$plan"

  # Then files
  while IFS=$'	' read -r typ rel existed oldog oldmode stagedmode; do
    [ "$typ" = "F" ] || continue
    target="/$rel"
    [ -e "$target" ] || continue

    if [ "$existed" -eq 1 ] && [ -n "$oldog" ] && [ -n "$oldmode" ]; then
      chown "$oldog" "$target" >/dev/null 2>&1 || true
      chmod "$oldmode" "$target" >/dev/null 2>&1 || true
    else
      dparent="$(dirname "$target")"
      parentog="$(nearest_parent_og "$dparent")"
      chown "$parentog" "$target" >/dev/null 2>&1 || true

      # Default file mode is parent_mode masked to rw bits (no execute): e.g. 755->644, 775->664
      pmode="$(stat -c '%a' "$dparent" 2>/dev/null || true)"
      if [ -n "$pmode" ]; then
        fmode="$(printf '%o' $((8#$pmode & 8#666)))"
      else
        fmode="644"
      fi

      # Scripts/menu launchers should be executable
      case "$target" in
        *.sh|*.rp) fmode="755" ;;
      esac

      chmod "$fmode" "$target" >/dev/null 2>&1 || true
    fi
  done < "$plan"
}

# ----------------------------
# Self-update (runs BEFORE applying update packs)
# ----------------------------
self_update_if_needed() {
  if [ "${SKIP_SELF_UPDATE:-0}" = "1" ]; then
    return 0
  fi
  [ "$SELF_UPDATE_ENABLED" -ne 1 ] && return 0

  local self_path
  self_path="$(readlink -f "$0" 2>/dev/null)"
  [ -z "$self_path" ] && return 0
  [ ! -f "$self_path" ] && return 0

  local tmp_script="/tmp/update_system.sh"

  if ! download_file "$SELF_UPDATE_URL" "$tmp_script"; then
    rm -f "$tmp_script" >/dev/null 2>&1
    return 0
  fi

  if [ "$CHECKSUM_VERIFY_ENABLED" -eq 1 ]; then
    if ! verify_checksum_for_download "update_system.sh" "/tmp"; then
      log_update "Updater checksum missing/failed. Skipping self-update."
      rm -f "$tmp_script" "/tmp/update_system.sh.sha256" >/dev/null 2>&1
      return 0
    fi
  fi


  # Record the expected hash for the updater itself (so republished updater can be detected)
  if [ "$CHECKSUM_VERIFY_ENABLED" -eq 1 ] && [ -f "/tmp/update_system.sh.sha256" ]; then
    local updater_expected_hash
    updater_expected_hash="$(parse_sha256_file_first_hash "/tmp/update_system.sh.sha256")"
    if [ -n "$updater_expected_hash" ]; then
      ensure_hash_log
      set_saved_hash "update_system.sh" "$updater_expected_hash"
    fi
  fi

  if ! cmp -s "$self_path" "$tmp_script" 2>/dev/null; then
    log_update "New updater detected. Installing and restarting updater."
    cp -f "$tmp_script" "$self_path" >/dev/null 2>&1
    chmod 755 "$self_path" >/dev/null 2>&1
    chown pi:pi "$self_path" >/dev/null 2>&1

    rm -f "$LOCKFILE" >/dev/null 2>&1
    SKIP_SELF_UPDATE=1 bash "$self_path" "$@"
    exit $?
  fi

  rm -f "$tmp_script" "/tmp/update_system.sh.sha256" >/dev/null 2>&1
  return 0
}

# ----------------------------
# Update list + sequencing
# ----------------------------
fetch_updates() {
  log_update "Fetching update list: $UPDATE_BASE_URL/update_version_list.txt"
  if ! download_file "$UPDATE_BASE_URL/update_version_list.txt" /tmp/update_version_list.txt; then
    log_update "Failed to fetch update list."
    show_message "Failed to fetch the update list.\n\n${LAST_DOWNLOAD_ERROR:-Check WiFi / internet connection.}"
    return 1
  fi
  return 0
}

get_missing_updates() {
  local current="$1"; shift
  local all=("$@")
  local found=0
  local missing=()

  for u in "${all[@]}"; do
    if [ "$found" -eq 1 ]; then
      missing+=("$u")
    fi
    if [ "$u" = "$current" ]; then
      found=1
    fi
  done

  if [ "$found" -eq 0 ]; then
    missing=("${all[@]}")
  fi

  printf '%s\n' "${missing[@]}"
}

# ----------------------------
# Apply updates
# ----------------------------
apply_updates() {
  local updates=("$@")
  [ ${#updates[@]} -eq 0 ] && return 1

  # Baseline roots so inheritance has sane parents
  apply_dir_baselines

  (
    # Ensure temp artifacts are cleaned up if we abort mid-update
    local __tmp_update="" __tmp_sha="" __perm_plan=""
    local __tmp_dir="$TEMP_UPDATE_DIR"
    cleanup_update_tmp() {
      [ -n "$__perm_plan" ] && rm -f "$__perm_plan" >/dev/null 2>&1
      [ -n "$__tmp_dir" ] && rm -rf "$__tmp_dir" >/dev/null 2>&1
      [ -n "$__tmp_update" ] && rm -f "$__tmp_update" >/dev/null 2>&1
      [ -n "$__tmp_sha" ] && rm -f "$__tmp_sha" >/dev/null 2>&1
    }
    trap cleanup_update_tmp EXIT

    local i=0
    local total=${#updates[@]}

    for update in "${updates[@]}"; do
      ((i++))
      local pct=$(( i * 100 / total ))
      echo "$pct"
      echo "XXX"
      echo "Applying update: $update ($i/$total)"
      echo "XXX"

      log_update "Processing update: $update"

      if ! is_valid_update_filename "$update"; then
        log_update "Invalid update filename rejected: $update"
        echo "100"; echo "XXX"; echo "Invalid update filename: $update"; echo "XXX"
        exit 1
      fi

      local tmp_update="/tmp/$update"
      __tmp_update="$tmp_update"
      __tmp_sha="/tmp/$update.sha256"
      rm -f "$tmp_update" >/dev/null 2>&1

      log_update "Downloading update package: $update"
      if ! download_file "$UPDATE_BASE_URL/$update" "$tmp_update"; then
        log_update "Failed to download $update"
        echo "100"; echo "XXX"; echo "Failed to download $update"; echo "XXX"
        exit 1
      fi

      if ! verify_checksum_for_download "$update" "/tmp"; then
        echo "100"; echo "XXX"; echo "Checksum failed for $update"; echo "XXX"
        exit 1
      fi

      # Remember expected hash for version+sha tracking
      local expected_hash
      expected_hash="$(parse_sha256_file_first_hash "/tmp/$update.sha256")"

      if ! validate_tarball_safe "$tmp_update"; then
        log_update "Tarball safety validation failed for $update"
        echo "100"; echo "XXX"; echo "Invalid update package: $update"; echo "XXX"
        exit 1
      fi

      rm -rf "$TEMP_UPDATE_DIR" >/dev/null 2>&1
      mkdir -p "$TEMP_UPDATE_DIR" >/dev/null 2>&1

      log_update "Extracting $update"
      tar -xzf "$tmp_update" -C "$TEMP_UPDATE_DIR" >/dev/null 2>&1
      if [ $? -ne 0 ]; then
        log_update "Failed to extract $update"
        echo "100"; echo "XXX"; echo "Failed to extract $update"; echo "XXX"
        exit 1
      fi

      # Build perm plan BEFORE apply (preserve existing)
      local perm_plan="/tmp/perm_plan_${$}.tsv"
      __perm_plan="$perm_plan"
      build_perm_plan "$TEMP_UPDATE_DIR" "$perm_plan"

      # Dependencies first
      if ! install_update_dependencies "$TEMP_UPDATE_DIR"; then
        log_update "Dependency install failed for $update"
        echo "100"; echo "XXX"; echo "Dependencies failed for $update"; echo "XXX"
        exit 1
      fi

      # Copy first
      log_update "Applying files to / (copy first)"
      rsync -rl \
        --exclude="${META_DIR_NAME}/" \
        --exclude="delete_list.txt" \
        --exclude="dependencies.txt" \
        "$TEMP_UPDATE_DIR/" / >/dev/null 2>&1
      if [ $? -ne 0 ]; then
        log_update "rsync failed for $update"
        echo "100"; echo "XXX"; echo "Failed to apply $update"; echo "XXX"
        exit 1
      fi

      # Delete second
      if ! process_delete_list "$TEMP_UPDATE_DIR"; then
        log_update "Delete list failed for $update"
        echo "100"; echo "XXX"; echo "Delete list failed for $update"; echo "XXX"
        exit 1
      fi

      # Permissions: Level B defaults, then optional per-update rules
      apply_perm_plan "$perm_plan"
      apply_permissions_from_meta "$TEMP_UPDATE_DIR"
      rm -f "$perm_plan" >/dev/null 2>&1


      # Ensure updater remains runnable
      if [ -f /home/pi/RetroPie/custom_scripts/update_system.sh ]; then
        chown pi:pi /home/pi/RetroPie/custom_scripts/update_system.sh >/dev/null 2>&1
        chmod 755 /home/pi/RetroPie/custom_scripts/update_system.sh >/dev/null 2>&1
      fi

      # Record version
      echo "$update" > "$LOCAL_VERSION_FILE"
      if [ -n "$expected_hash" ]; then
        set_saved_hash "$update" "$expected_hash"
      fi
      update_version_in_xml "$(clean_version_name "$update")"

      # Cleanup per-update temp
      strip_control_files "$TEMP_UPDATE_DIR"
      rm -rf "$TEMP_UPDATE_DIR" >/dev/null 2>&1
      rm -f "$tmp_update" "/tmp/$update.sha256" >/dev/null 2>&1
      __tmp_update=""; __tmp_sha=""; __perm_plan=""

      log_update "Update $update applied successfully."
    done

    echo "100"
    echo "XXX"
    echo "All selected updates applied successfully!"
    echo "XXX"
  ) | dialog --gauge "Applying updates..." 10 60 0

  local producer_rc=${PIPESTATUS[0]}
  local dialog_rc=${PIPESTATUS[1]}

  if [ $dialog_rc -ne 0 ]; then
    log_update "Update interrupted (dialog rc: $dialog_rc)"
    return 1
  fi
  if [ $producer_rc -ne 0 ]; then
    log_update "Update failed (producer rc: $producer_rc)"
    return 1
  fi

  return 0
}

# ----------------------------
# Lock + cleanup
# ----------------------------
cleanup() {
  rm -rf "$TEMP_UPDATE_DIR" >/dev/null 2>&1
  rm -f /tmp/update_version_list.txt >/dev/null 2>&1
  rm -f /tmp/update_system.sh /tmp/update_system.sh.sha256 >/dev/null 2>&1
  rm -f "$LOCKFILE" >/dev/null 2>&1
  log_update "Cleanup complete."
}

start_lock() {
  # Refuse symlink lockfile (defense-in-depth)
  if [ -L "$LOCKFILE" ]; then
    echo "Lockfile is not a regular file. Aborting."
    exit 1
  fi

  if [ -e "$LOCKFILE" ]; then
    local oldpid
    oldpid="$(cat "$LOCKFILE" 2>/dev/null)"
    if [[ "$oldpid" =~ ^[0-9]+$ ]] && kill -0 "$oldpid" 2>/dev/null; then
      echo "Update script is already running."
      exit 1
    fi
  fi

  echo $$ > "$LOCKFILE"
  trap "cleanup; exit" INT TERM EXIT
}

# ----------------------------
# UI menu
# ----------------------------
system_updates_menu() {
  # Enforce baseline ownership/modes (safe defaults) and any explicit file overrides
  apply_dir_baselines
  apply_file_permission_overrides

  ensure_file_exists "$LOCAL_VERSION_FILE" "UNKNOWN"
  ensure_file_exists "$LOG_FILE" ""
    ensure_hash_log

  while true; do
    OPTION=$(dialog --stdout --title "System Updates" --menu \
      "WARNING: Your arcade must be connected to WiFi for updates to download." \
      15 60 3 \
      1 "Check for Updates" \
      2 "View Update Log" \
      3 "View Current Version")

    [[ $? -ne 0 ]] && return

    case $OPTION in
      1)
        log_update "User selected Check for Updates"
        self_update_if_needed "${ORIGINAL_ARGS[@]}"
        if ! fetch_updates; then
          continue
        fi

        mapfile -t raw < /tmp/update_version_list.txt
        all_updates=()
        for line in "${raw[@]}"; do
          line="${line#"${line%%[![:space:]]*}"}"
          line="${line%"${line##*[![:space:]]}"}"
          [ -z "$line" ] && continue
          [[ "$line" =~ ^# ]] && continue
          if is_valid_update_filename "$line"; then
            all_updates+=("$line")
          else
            log_update "Ignored invalid update entry: $line"
          fi
        done

        if [ ${#all_updates[@]} -eq 0 ]; then
          show_message "Update list is empty or invalid.\n\nPlease contact Simple Arcades support."
          continue
        fi

        current_version="$(cat "$LOCAL_VERSION_FILE" 2>/dev/null)"
        [ -z "$current_version" ] && current_version="UNKNOWN"
        latest="${all_updates[${#all_updates[@]}-1]}"

        mapfile -t missing < <(get_missing_updates "$current_version" "${all_updates[@]}")

        if [ ${#missing[@]} -eq 0 ] || [ "$current_version" = "$latest" ]; then
          # Version is latest. If the package was republished (same version name, new sha256),
          # offer to re-apply it. This only triggers if we have a saved hash for this version.
          local saved_hash remote_hash
          saved_hash="$(get_saved_hash "$latest")"
          remote_hash="$(get_remote_hash "$latest")"
          if [ -n "$saved_hash" ] && [ -n "$remote_hash" ] && [ "$saved_hash" != "$remote_hash" ]; then
            missing=("$latest")
          else
            show_message "Your system is up-to-date! No updates available."
            continue
          fi
        fi

        msg="Update available.\n\nCurrent version: $(clean_version_name "$current_version")\nLatest version:  $(clean_version_name "$latest")\n\nThis will apply ${#missing[@]} update(s).\n\nDo you want to update to the latest version now?"
        dialog --yesno "$msg" 14 64
        if [ $? -ne 0 ]; then
          log_update "User canceled update"
          continue
        fi

        if apply_updates "${missing[@]}"; then
          dialog --yesno "Updates applied successfully. Do you want to reboot now?" 10 50
          if [ $? -eq 0 ]; then
            show_message "Rebooting your arcade."
            log_update "Rebooting after update"
            reboot
          else
            show_message "Reboot canceled. Please reboot manually to apply updates."
            log_update "User postponed reboot"
          fi
        else
          show_message "Failed to apply updates.\n\nPlease check the update log."
          log_update "Update failed"
        fi
        ;;
      2)
        log_update "User selected View Update Log"
        if [ ! -f "$LOG_FILE" ]; then
          show_message "No updates have been applied yet."
        else
          dialog --ok-button "OK" --title "Update Log" --textbox "$LOG_FILE" 20 70
        fi
        ;;
      3)
        log_update "User selected View Current Version"
        current_version="$(cat "$LOCAL_VERSION_FILE" 2>/dev/null)"
        [ -z "$current_version" ] && current_version="UNKNOWN"
        show_message "Your current system version is: $(clean_version_name "$current_version")"
        ;;
    esac
  done
}

# ----------------------------
# Main
# ----------------------------
ORIGINAL_ARGS=("$@")
start_lock
self_update_if_needed "$@"
system_updates_menu
cleanup
