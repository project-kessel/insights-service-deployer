#!/usr/bin/env bash

set -euo pipefail

# --- CONFIGURATION ---

# Endpoints
GATEWAY="http://localhost:8001"
HOSTS_READS_URL="http://localhost:8002/api/inventory/v1/hosts"
HOSTS_WRITES_URL="http://localhost:8003/api/inventory/v1/hosts"
PROXY_URL="$GATEWAY/api/inventory/v1/hosts"
WORKSPACES_URL="$GATEWAY/api/inventory/v1/groups"
WORKSPACES_READS_URL="http://localhost:8002/api/inventory/v1/groups"
WORKSPACES_WRITES_URL="http://localhost:8003/api/inventory/v1/groups"

# Workspace and Host UUIDs (set these to your actual values)
WORKSPACE_UUID="0197c57c-d458-7372-ac1f-0c981f0536e3"
HOST_UUID="8fdf25c7-eda8-48c2-8b04-1cecef9f7a5f"

# Simple user identities (working format from our previous sessions)
jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'

alice_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"alice","email":"alice@redhat.com","first_name":"Alice","last_name":"TeamA","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12347","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'

sara_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"sara","email":"sara@redhat.com","first_name":"Sara","last_name":"Support","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12346","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'

bob_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"bob","email":"bob@redhat.com","first_name":"Bob","last_name":"TeamB","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12348","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'

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

create_workspace() {
  local user_json="$1"
  local user="$2"
  local workspace_name="$3"
  local url="${4:-$WORKSPACES_WRITES_URL}"
  local header
  header=$(base64_header "$user_json")
  echo "---- $user: Creating workspace '$workspace_name' at $url ----"
  curl -s -X POST "$url" \
    -H "accept: application/json" \
    -H "Content-Type: application/json" \
    -H "x-rh-identity: $header" \
    -d "{\"name\":\"$workspace_name\",\"host_ids\":[]}" | jq .
  echo
}

list_workspaces() {
  local user_json="$1"
  local user="$2"
  local url="${3:-$WORKSPACES_URL}"
  local header
  header=$(base64_header "$user_json")
  echo "---- $user: Listing workspaces at $url ----"
  curl -s -o /tmp/workspaces_resp.json -w "%{http_code}" -H "x-rh-identity: $header" -H "Accept: application/json" "$url"
  echo
  if jq -e '.results' /tmp/workspaces_resp.json >/dev/null 2>&1; then
    local count=$(jq '.results | length' /tmp/workspaces_resp.json)
    echo "Workspace count: $count"
    echo "Workspaces:"
    jq -r '.results[] | "  - Name: \(.name), ID: \(.id), Host count: \(.host_count // 0)"' /tmp/workspaces_resp.json
  else
    cat /tmp/workspaces_resp.json
  fi
  echo
}

# --- PORT FORWARDING SETUP ---

setup_port_forwards() {
  echo "Setting up port forwards..."
  
  # Find the main host-inventory service pod (nginx proxy)
  MAIN_POD=$(oc get pods -l pod=host-inventory-service --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
  if [[ -z "$MAIN_POD" ]]; then
    echo "ERROR: Could not find running host-inventory-service pod"
    exit 1
  fi
  
  # Find the reads service pod
  READS_POD=$(oc get pods -l pod=host-inventory-service-reads --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
  if [[ -z "$READS_POD" ]]; then
    echo "ERROR: Could not find running host-inventory-service-reads pod"
    exit 1
  fi
  
  # Find the writes service pod
  WRITES_POD=$(oc get pods -l pod=host-inventory-service-writes --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
  if [[ -z "$WRITES_POD" ]]; then
    echo "ERROR: Could not find running host-inventory-service-writes pod"
    exit 1
  fi
  
  echo "Found pods:"
  echo "  Main service: $MAIN_POD"
  echo "  Reads service: $READS_POD"
  echo "  Writes service: $WRITES_POD"
  
  # Start port forwards in background
  echo "Starting port forward for main service (localhost:8001 -> $MAIN_POD:8080)..."
  oc port-forward pod/$MAIN_POD 8001:8080 >/dev/null 2>&1 &
  MAIN_PF_PID=$!
  
  echo "Starting port forward for reads service (localhost:8002 -> $READS_POD:8000)..."
  oc port-forward pod/$READS_POD 8002:8000 >/dev/null 2>&1 &
  READS_PF_PID=$!
  
  echo "Starting port forward for writes service (localhost:8003 -> $WRITES_POD:8000)..."
  oc port-forward pod/$WRITES_POD 8003:8000 >/dev/null 2>&1 &
  WRITES_PF_PID=$!
  
  # Wait for port forwards to establish
  sleep 3
  
  echo "Port forwards established"
}

# Cleanup function to kill port-forwards
cleanup_port_forwards() {
  echo "Cleaning up port forwards..."
  if [[ -n "${MAIN_PF_PID:-}" ]]; then
    kill "$MAIN_PF_PID" 2>/dev/null || true
  fi
  if [[ -n "${READS_PF_PID:-}" ]]; then
    kill "$READS_PF_PID" 2>/dev/null || true
  fi
  if [[ -n "${WRITES_PF_PID:-}" ]]; then
    kill "$WRITES_PF_PID" 2>/dev/null || true
  fi
}
trap cleanup_port_forwards EXIT 

assign_host_to_workspace() {
  local user_json="$1"
  local user="$2"
  local workspace_uuid="$3"
  local host_uuid="$4"
  local base_url="${5:-http://localhost:8003/api/inventory/v1}"
  local header
  header=$(base64_header "$user_json")
  echo "---- $user: Assigning host $host_uuid to workspace $workspace_uuid ----"
  curl -s -X POST "$base_url/groups/$workspace_uuid/hosts" \
    -H "accept: application/json" \
    -H "Content-Type: application/json" \
    -H "x-rh-identity: $header" \
    -d "[\"$host_uuid\"]" | jq .
  echo
}

# --- TEST FLOW ---

echo "=== E2E Inventory Test ==="

# Set up port forwarding for both deployed and dev pods
setup_port_forwards

# Need to replicate the actions taken on the console to test the API
# 0. List hosts
# 1. Create a workspace
# 2. Assign a host to the workspace
# 3. Get a user view permission for the host in that workspace
# 3. Check the users visibility, can they or cant they see the host?
# 4. Repeat the same actions with the Okteto dev pods
# 5. Check the host visibility, can they or cant they see the host?

echo "=== Baseline: Deployed Pods ==="

echo "=== Hosts ==="
list_hosts "$jdoe_json" "jdoe (admin)" "$HOSTS_READS_URL"
# list_hosts "$alice_json" "alice" "$HOSTS_READS_URL"
# list_hosts "$sara_json" "sara" "$HOSTS_READS_URL"
# list_hosts "$bob_json" "bob" "$HOSTS_READS_URL"

echo "=== Workspaces ==="
list_workspaces "$jdoe_json" "jdoe (admin)" "$WORKSPACES_READS_URL"
# list_workspaces "$alice_json" "alice" "$WORKSPACES_READS_URL"
# list_workspaces "$sara_json" "sara" "$WORKSPACES_READS_URL"
# list_workspaces "$bob_json" "bob" "$WORKSPACES_READS_URL"

echo "=== Create Workspace ==="
create_workspace "$jdoe_json" "jdoe" "Test-E2E-Workspace" "$WORKSPACES_WRITES_URL"

echo "=== Workspaces ==="
list_workspaces "$jdoe_json" "jdoe (admin)" "$WORKSPACES_READS_URL"

# echo "=== Assign Host to Workspace ==="
# assign_host_to_workspace "$jdoe_json" "jdoe" "$WORKSPACE_UUID" "$HOST_UUID"

echo "=== After Assignment: Check Host Visibility ==="
list_hosts "$jdoe_json" "jdoe (admin)" "$HOSTS_READS_URL"
# list_hosts "$alice_json" "alice" "$HOSTS_READS_URL"
# list_hosts "$sara_json" "sara" "$HOSTS_READS_URL"
# list_hosts "$bob_json" "bob" "$HOSTS_READS_URL"

# Modify default permissions to remove host admin permission (meaning they can only see hosts in their workspace)

# Add jdoe and sara to the new workspace


# check the host visibility, can they or cant they see the host?


# echo "=== After Assignment: Check Host Visibility ==="
# list_hosts "$jdoe_json" "jdoe (admin)"
# list_hosts "$alice_json" "alice (should NOT see hosts)"
# list_hosts "$sara_json" "sara"
# list_hosts "$bob_json" "bob (should NOT see hosts)"


## Run okteto up commands here
# echo "=== Okteto Dev Pods: Repeat E2E ==="
# (Assume you have already switched pods to dev mode and port-forwarded as needed)
# list_hosts "$jdoe_json" "jdoe (admin)" "$READS_URL"
# list_hosts "$alice_json" "alice (should NOT see hosts)" "$READS_URL"
# list_hosts "$sara_json" "sara" "$READS_URL"
# list_hosts "$bob_json" "bob (should NOT see hosts)" "$READS_URL"



echo "=== Done ==="
