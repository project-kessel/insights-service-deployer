#!/usr/bin/env bash

# Check if jq is installed
if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is not installed. Please install jq to continue." >&2
  exit 1
fi

# Check if bonfire is installed
if ! command -v bonfire >/dev/null 2>&1; then
  echo "Error: crc-bonfire is not installed. Please install crc-bonfire to continue." >&2
  exit 1
fi

check_status() {
  echo "Status: $HTTP_CODE"

  if [ "$HTTP_CODE" -eq 0 ]; then
    echo "Successfully."
  elif [ "$HTTP_CODE" -eq 22 ]; then
    echo "Error: Invalid data format."
    echo "$RESPONSE"
  elif [ "$HTTP_CODE" -eq 401 ]; then
    echo "Error: Unauthorized. Check your ACCESS_TOKEN."
  elif [ "$HTTP_CODE" -eq 403 ]; then
    echo "Error: Forbidden. Your token might not have the necessary permissions."
  elif [ "$HTTP_CODE" -ge 400 ]; then
    echo "Error: Bad request. HTTP Status Code: $HTTP_CODE"
    echo "Response: $RESPONSE"
  elif [ "$HTTP_CODE" -ge 500 ]; then
    echo "Error: Server error. HTTP Status Code: $HTTP_CODE"
    echo "Response: $RESPONSE"
  else
    echo "Error: Curl request failed with exit code: $HTTP_CODE"
    echo "Response: $RESPONSE"
  fi
}

RBAC_FILE="./data/rbac_group_role.json"
# --- Check if the JSON file exists ---
if [ ! -f "$RBAC_FILE" ]; then
  echo "Error: JSON file '$RBAC_FILE' not found."
  exit 1
fi

# Getting all Keycloak vars from `bonfire namespace describe` result
json_output=$(bonfire namespace describe -o json)

# Export environment variables from keys containing "keycloak_admin"
eval $(echo "$json_output" | jq -r '
  to_entries[]
  | select(.key | test("gateway") or test("keycloak_admin"))
  | "\(.key | ascii_upcase)=\(.value | @sh)"'
)

RBAC_ROUTE="$GATEWAY_ROUTE/api/rbac"
echo "$RBAC_ROUTE"

# Getting the first org_admin credentials
IDENTITY=$(jq 'map(select(.attributes.is_org_admin == true))[0]' ./data/rbac_users_data.json )
ADMIN_USERNAME=$(echo "$IDENTITY" | jq -r '.username')
ADMIN_PASSWORD=$(echo "$IDENTITY" | jq -r '.credentials[0].value')

# Get the ACCESS TOKEN from Keycloak
REALM_NAME="redhat-external"
CLIENT_ID="cloud-services"

TOKEN_RESPONSE=$(curl -s -X POST \
  "${KEYCLOAK_ADMIN_ROUTE}/realms/${REALM_NAME}/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=password&username=${ADMIN_USERNAME}&password=${ADMIN_PASSWORD}&client_id=${CLIENT_ID}")

if [ $? -ne 0 ]; then
  echo "Error fetching access token."
  echo "$TOKEN_RESPONSE"
  exit 1
fi

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [ -z "$ACCESS_TOKEN" ]; then
  echo "Failed to extract access token."
  echo "$TOKEN_RESPONSE"
  exit 1
fi

echo "Successfully obtained Access Token."
echo "ACCESS_TOKEN: $ACCESS_TOKEN"

# Getting/Creating RBAC Group
RBAC_GROUP=$(cat "$RBAC_FILE" | jq -r '.group')
RBAC_GROUP_NAME=$(echo "$RBAC_GROUP" | jq -r ".name")

RBAC_GROUP_UUID=$(curl -s -H "accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "${RBAC_ROUTE}/v1/groups/?name=${RBAC_GROUP_NAME}&name_match=exact" | jq -r '.data[0].uuid'
)
if [ "$RBAC_GROUP_UUID" = "null" ]; then
  RBAC_GROUP_UUID=$(curl -s -H "accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    "${RBAC_ROUTE}/v1/groups/" -X POST \
    -d "$RBAC_GROUP" | jq -r '.uuid'
  )
  HTTP_CODE=$?
  check_status
fi
echo "RBAC Group: $RBAC_GROUP_UUID"

# Getting/Creating RBAC Group
RBAC_ROLE=$(cat "$RBAC_FILE" | jq -r '.role')
RBAC_ROLE_NAME=$(echo "$RBAC_ROLE" | jq -r ".name")

RBAC_ROLE_UUID=$(curl -s -H "accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "${RBAC_ROUTE}/v1/roles/?name=${RBAC_ROLE_NAME}&name_match=exact" | jq -r '.data[0].uuid'
)
if [ "$RBAC_ROLE_UUID" = "null" ]; then
  RBAC_ROLE_UUID=$(curl -s -H "accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    "${RBAC_ROUTE}/v1/roles/" -X POST \
    -d "$RBAC_ROLE" | jq -r '.uuid'
  )
  HTTP_CODE=$?
  check_status
fi
echo "RBAC Role: $RBAC_ROLE_UUID"

# Adding the Role to the Group
RESPONSE=$(curl -s -H "accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "${RBAC_ROUTE}/v1/groups/${RBAC_GROUP_UUID}/roles/" -X POST \
  -d "{\"roles\": [\"${RBAC_ROLE_UUID}\"]}")

HTTP_CODE=$?
check_status

# Adding the Principals to the Group
RBAC_PRINCIPALS=$(cat "$RBAC_FILE" | jq -r '.principals')

RESPONSE=$(curl -s -H "accept: application/json" -H "Content-Type: application/json" -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  "${RBAC_ROUTE}/v1/groups/${RBAC_GROUP_UUID}/principals/" -X POST \
  -d "$RBAC_PRINCIPALS")

HTTP_CODE=$?
check_status
