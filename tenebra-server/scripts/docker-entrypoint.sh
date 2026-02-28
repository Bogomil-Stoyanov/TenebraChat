#!/bin/sh
set -e

echo "Running database migrations..."
node scripts/migrate.js

echo "Starting Tenebra server..."
exec node dist/index.js
