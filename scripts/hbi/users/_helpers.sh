#!/bin/bash

# _helpers.sh
# This script contains common functions for interacting with platform services.
#
# It assumes you are logged into an OpenShift environment and have `oc` and `jq` CLIs available.
#
# Required environment variables:
# - BASE_URL: The base URL for the API endpoints (e.g., http://localhost:8080)

# Function to log messages
log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" >&2
}

# Function to get an authentication token from the current OpenShift session
get_token() {
    log "Getting token using 'oc' command..."

    if ! command -v oc &> /dev/null; then
        log "Error: 'oc' command not found. Please install the OpenShift CLI and ensure it's in your PATH."
        return 1
    fi

    local token
    token=$(oc whoami --show-token 2>/dev/null)

    if [[ -z "$token" ]]; then
        log "Error: Failed to get token using 'oc'. Make sure you are logged into your OpenShift cluster."
        return 1
    fi

    echo "$token"
}

# Function to create a group
create_group() {
    local token=$1
    local group_name=$2
    local group_description=$3
    log "Creating group: $group_name"

    if [[ -z "$BASE_URL" ]]; then
        log "Error: BASE_URL environment variable is not set."
        return 1
    fi

    local response
    response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/api/rbac/v1/groups/" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$group_name\", \"description\": \"$group_description\"}")

    local http_code=${response: -3}
    local body=${response::-3}

    if [[ "$http_code" -ne 201 ]]; then
        log "Error creating group. Status: $http_code, Body: $body"
        return 1
    fi

    echo "$body" | jq -r '.uuid'
}

# Function to add a user to a group
add_user_to_group() {
    local token=$1
    local group_uuid=$2
    local principal_id=$3
    log "Adding user $principal_id to group $group_uuid"

    if [[ -z "$BASE_URL" ]]; then
        log "Error: BASE_URL environment variable is not set."
        return 1
    fi

    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/api/rbac/v1/groups/$group_uuid/principals/" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "{\"principals\": [\"$principal_id\"]}")

    if [[ "$response" -ne 200 ]]; then
        log "Error adding user to group. Status: $response"
        return 1
    fi
}

# Function to add a role to a group
add_role_to_group() {
    local token=$1
    local group_uuid=$2
    local role_name=$3
    log "Adding role $role_name to group $group_uuid"

    if [[ -z "$BASE_URL" ]]; then
        log "Error: BASE_URL environment variable is not set."
        return 1
    fi

    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/api/rbac/v1/groups/$group_uuid/roles/" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "{\"roles\": [\"$role_name\"]}")

    if [[ "$response" -ne 200 ]]; then
        log "Error adding role to group. Status: $response"
        return 1
    fi
} 