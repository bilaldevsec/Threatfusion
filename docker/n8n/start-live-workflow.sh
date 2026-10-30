#!/bin/sh
# Import the live-console workflow, then start n8n so the webhook is registered.
set -eu
n8n import:workflow --input=/import/threatfusion_live_console_playbook.json
n8n update:workflow --id=threatfusion-live-console --active=true
exec n8n start
