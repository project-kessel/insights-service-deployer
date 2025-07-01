#!/usr/bin/env bash

set -euo pipefail

# --- CONFIGURATION ---

# Endpoints
GATEWAY="http://localhost:8001"
READS_URL="http://localhost:8002/api/inventory/v1/hosts"
PROXY_URL="$GATEWAY/api/inventory/v1/hosts"

# Workspace and Host UUIDs (set these to your actual values)
WORKSPACE_UUID="0197c57c-d458-7372-ac1f-0c981f0536e3"
HOST_UUID="8fdf25c7-eda8-48c2-8b04-1cecef9f7a5f"

# User identity JSONs (from rbac_users_data.json)
jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345"}}}'
alice_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"alice","email":"alice@redhat.com","first_name":"Alice","last_name":"TeamA","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12347"}}}'
sara_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"sara","email":"sara@redhat.com","first_name":"Sara","last_name":"Support","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12346"}}}'
bob_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"bob","email":"bob@redhat.com","first_name":"Bob","last_name":"TeamB","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12348"}}}'

# --- FUNCTIONS ---

base64_header() {
  echo -n "$1" | base64 -w 0
}

list_hosts() {
  local user_json="$1"
  local user="$2"
  local url="${3:-$PROXY_URL}"
  local header
  header=$(base64_header "$user_json")
  echo "---- $user: Listing hosts at $url ----"
  curl -s -o /tmp/resp.json -w "%{http_code}" -H "x-rh-identity: $header" -H "Accept: application/json" "$url"
  echo
  if jq -e '.results' /tmp/resp.json >/dev/null 2>&1; then
    local count=$(jq '.results | length' /tmp/resp.json)
    echo "Host count: $count"
    echo "Host IDs:"
    jq -r '.results[].id' /tmp/resp.json
  else
    cat /tmp/resp.json
  fi
  echo
}

# --- PORT FORWARDING SETUP ---

# Function to check if a port is already being forwarded
is_port_forwarded() {
  local port="$1"
  lsof -iTCP:"$port" -sTCP:LISTEN -P | grep -q LISTEN
}

# Function to start port-forward if not already running
start_port_forward() {
  local pod_name="$1"
  local local_port="$2"
  local pod_port="$3"
  local label="$4"

  if is_port_forwarded "$local_port"; then
    echo "[INFO] Port $local_port is already being forwarded."
  else
    # Find the pod name
    pod=$(oc get pods --no-headers -o custom-columns=":metadata.name" -l pod="$pod_name" | grep Running | head -1)
    if [ -z "$pod" ]; then
      echo "[ERROR] Could not find running pod for $pod_name."
      exit 1
    fi
    echo "[INFO] Starting port-forward for $label ($pod: $local_port -> $pod_port) ..."
    oc port-forward pod/$pod $local_port:$pod_port >/dev/null 2>&1 &
    pf_pid=$!
    echo $pf_pid > "/tmp/pf_${label}_$local_port.pid"
    # Wait a moment for port-forward to establish
    sleep 2
  fi
}

# Cleanup function to kill port-forwards
cleanup_port_forwards() {
  for pf in /tmp/pf_*_*.pid; do
    if [ -f "$pf" ]; then
      pf_pid=$(cat "$pf")
      kill "$pf_pid" 2>/dev/null || true
      rm -f "$pf"
    fi
  done
}
trap cleanup_port_forwards EXIT

# # Start port-forwards if needed
# Need to get port forwarding working with the script itself instead of manually

# start_port_forward "host-inventory-service" 8001 8080 "main"
# start_port_forward "host-inventory-service-reads" 8002 8000 "reads" 

assign_host_to_workspace() {
  local user_json="$1"
  local user="$2"
  local workspace_uuid="$3"
  local host_uuid="$4"
  local header
  header=$(base64_header "$user_json")
  echo "---- $user: Assigning host $host_uuid to workspace $workspace_uuid ----"
  curl -s -X POST "$GATEWAY/api/inventory/v1/groups/$workspace_uuid/hosts" \
    -H "accept: application/json" \
    -H "Content-Type: application/json" \
    -H "x-rh-identity: $header" \
    -d "[\"$host_uuid\"]" | jq .
  echo
}

# --- TEST FLOW ---


# Need to replicate the actions taken on the console to test the API
# 1. Create a workspace
# 2. Assign a host to the workspace
# 3. Get a user view permission for the host in that workspace
# 3. Check the users visibility, can they or cant they see the host?
# 4. Repeat the same actions with the Okteto dev pods
# 5. Check the host visibility, can they or cant they see the host?
# 6. Repeat the same actions with the Okteto dev pods
# 7. Check the host visibility, can they or cant they see the host?

# echo "=== Baseline: Deployed Pods ==="
# list_hosts "$jdoe_json" "jdoe (admin)"
# list_hosts "$alice_json" "alice (should NOT see hosts)"
# list_hosts "$sara_json" "sara"
# list_hosts "$bob_json" "bob (should NOT see hosts)"

# # echo "=== Assign Host to Workspace as jdoe ==="
# # assign_host_to_workspace "$jdoe_json" "jdoe" "$WORKSPACE_UUID" "$HOST_UUID"

# echo "=== After Assignment: Check Host Visibility ==="
# list_hosts "$jdoe_json" "jdoe (admin)"
# list_hosts "$alice_json" "alice (should NOT see hosts)"
# list_hosts "$sara_json" "sara"
# list_hosts "$bob_json" "bob (should NOT see hosts)"

echo "=== Okteto Dev Pods: Repeat E2E ==="
# (Assume you have already switched pods to dev mode and port-forwarded as needed)
list_hosts "$jdoe_json" "jdoe (admin)" "$READS_URL"
list_hosts "$alice_json" "alice (should NOT see hosts)" "$READS_URL"
list_hosts "$sara_json" "sara" "$READS_URL"
list_hosts "$bob_json" "bob (should NOT see hosts)" "$READS_URL"

echo "=== Done ==="
