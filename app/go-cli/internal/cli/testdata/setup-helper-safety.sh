set -eu
helper=/usr/local/libexec/shuttle-root
cleanup=/var/lib/shuttle/operations/destroy-cleanup
refuse_helper_replacement() {
  echo 'helper replacement refused while destroy cleanup evidence remains; recover with the installed helper first: docs/operations-recovery.md' >&2
  exit 1
}
if [ -e "$helper" ] || [ -L "$helper" ]; then
  if [ -e "$cleanup" ] || [ -L "$cleanup" ]; then
    [ -d "$cleanup" ] && [ ! -L "$cleanup" ] && [ -r "$cleanup" ] && [ -x "$cleanup" ] && [ "$(stat -c '%u:%a' "$cleanup")" = '0:700' ] || refuse_helper_replacement
    for entry in "$cleanup"/* "$cleanup"/.[!.]* "$cleanup"/..?*; do
      [ -e "$entry" ] || [ -L "$entry" ] || continue
      name=${entry##*/}
      case "$name" in
        .shuttle-root-*)
          suffix=${name#.shuttle-root-}
          case "$suffix" in ''|*[!0-9]*) refuse_helper_replacement ;; esac
          [ -f "$entry" ] && [ ! -L "$entry" ] && [ "$(stat -c '%u:%a' "$entry")" = '0:600' ] || refuse_helper_replacement
          ;;
        *) refuse_helper_replacement ;;
      esac
    done
  fi
fi
