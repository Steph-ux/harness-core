#!/bin/sh
# Capture a recorded trace in an isolated Xvfb terminal when available.
#
# Usage: capture_terminal.sh <display> <cwd> <title> <text-file> <dest>
#
# Uses a private Xvfb display by default (HARNESS_CAPTURE_XVFB != "off") so
# qterminal never touches the operator's live DISPLAY or steals foreground focus.
set -eu

DISPLAY_ARG=${1:-}
CWD=$2
TITLE=$3
TEXT=$4
DEST=$5

if [ "${HARNESS_CAPTURE_XVFB:-auto}" != "off" ] && [ -z "${_HARNESS_IN_XVFB:-}" ] && command -v xvfb-run >/dev/null 2>&1; then
  export _HARNESS_IN_XVFB=1
  exec xvfb-run -a -s "-screen 0 1280x800x24" sh "$0" "$@"
fi

if [ -z "${_HARNESS_IN_XVFB:-}" ]; then
  if [ -n "$DISPLAY_ARG" ]; then
    DISPLAY=$DISPLAY_ARG
    export DISPLAY
  fi
  [ -n "${DISPLAY:-}" ] || { echo "no display" >&2; exit 1; }
fi

LINES=$(wc -l < "$TEXT")
HEIGHT=$((30 + LINES * 18 + 40))
[ "$HEIGHT" -lt 220 ] && HEIGHT=220

BEFORE=$(xdotool search --onlyvisible --class qterminal 2>/dev/null | tr '\n' ' ' || true)
PID=""
cleanup() {
  if [ -n "${PID:-}" ]; then
    pkill -TERM -P "$PID" 2>/dev/null || true
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

qterminal -w "$CWD" -e sh -c 'printf "\033]0;%s\007" "$1"; clear; cat "$2"; sleep 25' _ "$TITLE" "$TEXT" >/dev/null 2>&1 &
PID=$!

WID=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  sleep 0.3
  WID=$(xdotool search --onlyvisible --pid "$PID" --class qterminal 2>/dev/null | head -n 1 || true)
  if [ -z "$WID" ]; then
    for id in $(xdotool search --onlyvisible --class qterminal 2>/dev/null || true); do
      case " $BEFORE " in *" $id "*) ;; *) WID=$id; break ;; esac
    done
  fi
  [ -n "$WID" ] && break
done
[ -n "$WID" ] || { echo "no terminal window" >&2; exit 1; }

xdotool windowsize "$WID" 1000 "$HEIGHT"
xdotool windowmove "$WID" 40 40
# The size hint of the terminal fades after the resize; wait for it.
sleep 2.5

xdotool windowraise "$WID" 2>/dev/null || true
sleep 0.3

ROOT_ID=$(xwininfo -root | awk '/Window id:/{print $4; exit}')
PARENT=$(xwininfo -id "$WID" -tree | awk '/Parent window id/{print $4; exit}')
FRAME=$WID
if [ -n "${PARENT:-}" ] && [ "$PARENT" != "${ROOT_ID:-}" ]; then
  PARENT_DEC=$(printf '%d' "$PARENT" 2>/dev/null || echo 0)
  ROOT_DEC=$(printf '%d' "${ROOT_ID:-0}" 2>/dev/null || echo -1)
  if [ "$PARENT_DEC" != "$ROOT_DEC" ]; then
    FRAME=$PARENT
  fi
fi

# Capture the terminal window/frame only, never the root window.
import -window "$FRAME" "$DEST"
[ -s "$DEST" ] || { echo "capture is empty" >&2; exit 1; }
