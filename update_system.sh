#!/bin/bash
# Simple Arcades - System Updater (Customer Facing)
# SCRIPT_BUILD=2026-01-13-v4 (tar validator fix + version+sha reapply)
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
UPDATE_BASE_URL="https://raw.githubusercontent.com/simple-arcades/updates_gen_3/main"

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
  local dir owner_group perm owner group
  for dir in "${!DIR_PERMISSIONS[@]}"; do
    [ -d "$dir" ] || continue
    IFS=' ' read -r owner_group perm <<< "${DIR_PERMISSIONS[$dir]}"
    IFS=':' read -r owner group <<< "$owner_group"
    chown "$owner":"$group" "$dir" >/dev/null 2>&1
    chmod "$perm" "$dir" >/dev/null 2>&1
  done
}

apply_file_permission_overrides() {
  local f owner_group perm owner group
  for f in "${!FILE_PERMISSIONS[@]}"; do
    if [ -e "$f" ]; then
      IFS=' ' read -r owner_group perm <<< "${FILE_PERMISSIONS[$f]}"
      IFS=':' read -r owner group <<< "$owner_group"
      chown "$owner":"$group" "$f" >/dev/null 2>&1
      chmod "$perm" "$f" >/dev/null 2>&1
    fi
  done
}

download_file() {
  local url="$1"
  local out="$2"

  rm -f "$out" >/dev/null 2>&1
  wget -q \
    --timeout="$WGET_TIMEOUT" \
    --tries="$WGET_TRIES" \
    --dns-timeout="$WGET_TIMEOUT" \
    --connect-timeout="$WGET_TIMEOUT" \
    --read-timeout="$WGET_TIMEOUT" \
    -O "$out" "$url" >/dev/null 2>&1

  if [ $? -ne 0 ] || [ ! -s "$out" ]; then
    rm -f "$out" >/dev/null 2>&1
    return 1
  fi
  return 0
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

  local checksum_url="$UPDATE_BASE_URL/$filename.sha256"
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
  rm -f "$root/delete_list.txt" "$root/dependencies.txt" >/dev/null 2>&1
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
  local typ rel existed oldog oldmode stagedmode target parentog dparent

  # Directories first
  awk -F'\t' '$1=="D"{print}' "$plan" | while IFS=$'\t' read -r typ rel existed oldog oldmode stagedmode; do
    target="/$rel"
    [ -d "$target" ] || continue

    if [ "$existed" -eq 1 ] && [ -n "$oldog" ] && [ -n "$oldmode" ]; then
      chown "$oldog" "$target" >/dev/null 2>&1
      chmod "$oldmode" "$target" >/dev/null 2>&1
    else
      dparent="$(dirname "$target")"
      parentog="$(nearest_parent_og "$dparent")"
      chown "$parentog" "$target" >/dev/null 2>&1
      [ -n "$stagedmode" ] && chmod "$stagedmode" "$target" >/dev/null 2>&1
    fi
  done

  # Then files
  awk -F'\t' '$1=="F"{print}' "$plan" | while IFS=$'\t' read -r typ rel existed oldog oldmode stagedmode; do
    target="/$rel"
    [ -e "$target" ] || continue

    if [ "$existed" -eq 1 ] && [ -n "$oldog" ] && [ -n "$oldmode" ]; then
      chown "$oldog" "$target" >/dev/null 2>&1
      chmod "$oldmode" "$target" >/dev/null 2>&1
    else
      dparent="$(dirname "$target")"
      parentog="$(nearest_parent_og "$dparent")"
      chown "$parentog" "$target" >/dev/null 2>&1
      [ -n "$stagedmode" ] && chmod "$stagedmode" "$target" >/dev/null 2>&1
    fi
  done
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
    show_message "Failed to fetch the update list.\n\nCheck WiFi / internet connection."
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
      build_perm_plan "$TEMP_UPDATE_DIR" "$perm_plan"

      # Dependencies first
      if ! install_update_dependencies "$TEMP_UPDATE_DIR"; then
        log_update "Dependency install failed for $update"
        echo "100"; echo "XXX"; echo "Dependencies failed for $update"; echo "XXX"
        exit 1
      fi

      # Copy first
      log_update "Applying files to / (copy first)"
      rsync -rlp \
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

      # Permissions: Level B, then baselines, then explicit overrides
      apply_perm_plan "$perm_plan"
      rm -f "$perm_plan" >/dev/null 2>&1

      apply_dir_baselines
      apply_file_permission_overrides

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
start_lock
self_update_if_needed "$@"
system_updates_menu
cleanup
