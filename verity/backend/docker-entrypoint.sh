#!/bin/bash
set -e

# Fix ownership of the data directory after Docker mounts the volume over it.
# This runs as root before we drop privileges.
chown -R verity:verity /app/data

# Drop to the non-root user and execute the main command.
exec gosu verity "$@"
