#!/bin/sh
set -e
# The base image's /start-postgres.sh isn't its entrypoint, so the backend
# starts its embedded Postgres itself (database, user, password, port as in
# the security config's credentials.postgres.creds.l8tunnel), then execs.
/start-postgres.sh l8tunnel l8tunnel l8tunnel 5432
exec /home/run/l8tunnel
