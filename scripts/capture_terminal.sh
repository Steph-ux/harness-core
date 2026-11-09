#!/bin/sh
# Capture a recorded trace in the operator's real terminal, decorations included.
#
# Usage: capture_terminal.sh <display> <cwd> <title> <text-file> <dest>
#
# The terminal is the operator's own (qterminal, with its profile and theme).
# It shows the recorded text, not a re-run, and it is closed as soon as the
# window is captured. Exit non-zero when the window or the capture is missing,
# so the caller can fall back to a printed rendering.
set -eu

DISPLAY=$1
CWD=$2
TITLE=$3
TEXT=$4
DEST=$5
export DISPLAY

LINES=$(wc -l < "$TEXT")
HEIGHT=$((30 + LINES * 18 + 40))
[ "$HEIGHT" -lt 220 ] && HEIGHT=220

BEFORE=$(xdotool search --onlyvisible --class qterminal 2>/dev/null | tr '\n' ' ' || true)
qterminal -w "$CWD" -e "sh -c 'printf \"\\033]0;%s\\007\" \"$TITLE\"; clear; cat \"$TEXT\"; sleep 25'" >/dev/null 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT INT TERM

WID=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  sleep 0.4
  for id in $(xdotool search --onlyvisible --class qterminal 2>/dev/null || true); do
    case " $BEFORE " in *" $id "*) ;; *) WID=$id ;; esac
  done
  [ -n "$WID" ] && break
done
[ -n "$WID" ] || { echo "no terminal window" >&2; exit 1; }

xdotool windowsize "$WID" 1000 "$HEIGHT"
xdotool windowmove "$WID" 40 40
# The size hint of the terminal fades after the resize; wait for it.
sleep 2.5

xdotool windowraise "$WID" 2>/dev/null || true
sleep 0.3
FRAME=$(xwininfo -id "$WID" -tree | awk '/Parent window id/{print $4; exit}')
[ -n "${FRAME:-}" ] || FRAME=$WID
# Capture the frame itself: decorations included, no overlapping window.
import -window "$FRAME" "$DEST"
[ -s "$DEST" ] || { echo "capture is empty" >&2; exit 1; }
