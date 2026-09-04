#!/usr/bin/env bash
# Non-active Safe YOLO 3.0 deny-only Cursor candidate. Replace placeholders
# only through operator maintenance after install.
exec /usr/bin/python3 /home/dev/.safe-yolo/bootstrap.py \
  --release /home/dev/.safe-yolo/releases/3.0.0-alpha.5 \
  --manifest-sha256 REPLACE_AFTER_INSTALL \
  --entry cursor_v3 \
  --state-dir /home/dev/.safe-yolo/state
