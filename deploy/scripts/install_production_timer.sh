#!/usr/bin/env bash
# Install the host-timer dispatcher as systemd user units, disabled and inactive.
#
#   deploy/scripts/install_production_timer.sh [--root DIR] [--force]
#
# DIR is the deployment root (the directory with docker-compose.yaml, .env and
# .local/). It defaults to $EVERGARDEN_ROOT, then to the checkout that contains
# this script. The units are rendered with that absolute path. An installed unit
# whose content differs is left alone unless --force is given.
#
# Use either this timer or the in-stack `scheduler` compose profile, not both.
# Enable afterwards with:
#   systemctl --user enable --now evergarden-production-dispatch.timer
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
evergarden_root="${EVERGARDEN_ROOT:-$(CDPATH= cd -- "$script_dir/../.." && pwd)}"
force=0
units="${SYSTEMD_USER_UNIT_DIR:-$HOME/.config/systemd/user}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      [[ $# -ge 2 ]] || { echo "--root needs a directory" >&2; exit 2; }
      evergarden_root="$2"
      shift 2
      ;;
    --root=*)
      evergarden_root="${1#--root=}"
      shift
      ;;
    --force)
      force=1
      shift
      ;;
    -h|--help)
      sed -n '2,13p' "$0"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

evergarden_root="$(CDPATH= cd -- "$evergarden_root" && pwd)"
if [[ ! -f "$evergarden_root/docker-compose.yaml" ]]; then
  echo "$evergarden_root has no docker-compose.yaml" >&2
  exit 1
fi
case "$evergarden_root" in
  *[[:space:]\|\&\;]*)
    echo "deployment root must not contain whitespace or shell/sed metacharacters" >&2
    exit 1
    ;;
esac

templates="$evergarden_root/deploy/systemd"
install -d -m 755 "$units"
rendered="$(mktemp -d)"
trap 'rm -rf "$rendered"' EXIT
changed=0
for unit in evergarden-production-dispatch.service evergarden-production-dispatch.timer evergarden-dispatch-alarm.service; do
  sed "s|@EVERGARDEN_ROOT@|$evergarden_root|g" "$templates/$unit" >"$rendered/$unit"
  if [[ -e "$units/$unit" ]] && ! cmp -s "$rendered/$unit" "$units/$unit"; then
    if [[ "$force" -ne 1 ]]; then
      echo "$units/$unit exists with different content; kept (use --force to replace)" >&2
      continue
    fi
  fi
  install -m 644 "$rendered/$unit" "$units/$unit"
  changed=1
done

if [[ "${EVERGARDEN_SKIP_SYSTEMCTL:-0}" == "1" ]]; then
  echo "units rendered for $evergarden_root into $units (systemctl skipped)"
  exit 0
fi
if [[ "$changed" -eq 1 ]]; then
  systemctl --user daemon-reload
fi
if systemctl --user is-enabled --quiet evergarden-production-dispatch.timer; then
  echo "dispatch timer is already enabled; left as is"
  exit 0
fi
if systemctl --user is-active --quiet evergarden-production-dispatch.timer; then
  echo "dispatch timer is unexpectedly active" >&2
  exit 1
fi
echo "dispatch timer installed for $evergarden_root, disabled and inactive"
