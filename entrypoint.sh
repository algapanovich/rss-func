#!/bin/sh

# This script prepares and starts the web service.
# It is designed to be the ENTRYPOINT for the Docker container.

# Exit immediately if any command fails, which is a best practice.
set -e

# This block enables verbose debug output if the DEBUG environment
# variable is set to "yes". You can set this in Cloud Run.
if [ "${DEBUG}" = "yes" ]; then
    set -x
else
    set +x
fi


# The 'exec "$@"' command below executes that 'gunicorn' command.


echo "Entrypoint script finished. Starting the main process..."
exec "$@"