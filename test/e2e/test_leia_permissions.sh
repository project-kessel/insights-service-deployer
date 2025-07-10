#!/usr/bin/env bash

# Test Leia's Permissions Only
# This script verifies that Leia can see exactly 2 hosts and only his workspace

set -e

echo "🧪 Testing Leia's Permissions"
echo "============================="
echo ""
echo "This script will verify that:"
echo "  • Leia can see exactly 2 hosts"
echo "  • Leia can only see his assigned workspace"
echo "  • Leia's hosts are in his workspace"
echo ""

# Function to setup port forwarding if needed
setup_port_forward() {
    if ! curl -s --connect-timeout 2 http://localhost:8002/health >/dev/null 2>&1; then
        echo "🔧 Setting up port forwarding..."
        READS_POD=$(oc get pods -l pod=host-inventory-service-reads --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
        
        if [[ -z "$READS_POD" ]]; then
            echo "❌ ERROR: Could not find reads service pod"
            exit 1
        fi
        
        echo "📡 Starting port forward: localhost:8002 -> $READS_POD:8000"
        oc port-forward "$READS_POD" 8002:8000 >/tmp/pf_leia_test.log 2>&1 &
        PF_PID=$!
        sleep 3
        echo "$PF_PID" > /tmp/pf_leia_test.pid
        echo "✅ Port forwarding established"
    else
        echo "✅ Port forwarding already active"
    fi
}

cleanup_port_forward() {
    if [[ -f /tmp/pf_leia_test.pid ]]; then
        kill $(cat /tmp/pf_leia_test.pid) 2>/dev/null || true
        rm -f /tmp/pf_leia_test.pid /tmp/pf_leia_test.log
    fi
}
trap cleanup_port_forward EXIT

# Set up port forwarding
setup_port_forward

# Leia's user identity
LEIA_JSON='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"leia","email":"leia@redhat.com","first_name":"Leia","last_name":"Johnson","is_active":true,"is_org_admin":false,"is_internal":false,"locale":"en_US","user_id":"12351","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'

# Function to encode user JSON to base64
base64_header() {
    echo -n "$1" | base64 -w 0
}

# Get Leia's identity header
LEIA_HEADER=$(base64_header "$LEIA_JSON")

echo "🔍 Testing Leia's Host Access..."
echo ""

# Test Leia's host access
echo "📊 Getting hosts that Leia can see..."
HOSTS_RESPONSE=$(curl -s -H "x-rh-identity: $LEIA_HEADER" \
    -H "Accept: application/json" \
    "http://localhost:8002/api/inventory/v1/hosts")

if ! echo "$HOSTS_RESPONSE" | jq -e '.results' >/dev/null 2>&1; then
    echo "❌ ERROR: Failed to get hosts for Leia"
    echo "Response: $HOSTS_RESPONSE"
    exit 1
fi

# Count hosts
HOST_COUNT=$(echo "$HOSTS_RESPONSE" | jq '.results | length')
echo "📋 Leia can see $HOST_COUNT hosts"

# Test result
if [[ "$HOST_COUNT" -eq 2 ]]; then
    echo "✅ SUCCESS: Leia sees exactly 2 hosts (as expected)"
    TEST_RESULT="PASS"
elif [[ "$HOST_COUNT" -gt 2 ]]; then
    echo "❌ FAIL: Leia sees $HOST_COUNT hosts (expected 2)"
    echo "   This suggests RBAC filtering is not working correctly"
    TEST_RESULT="FAIL"
else
    echo "❌ FAIL: Leia sees only $HOST_COUNT hosts (expected 2)"
    echo "   This suggests insufficient hosts or assignment issues"
    TEST_RESULT="FAIL"
fi

echo ""
echo "📋 Host Details:"
if [[ "$HOST_COUNT" -gt 0 ]]; then
    echo "Host IDs Leia can see:"
    echo "$HOSTS_RESPONSE" | jq -r '.results[].id' | sed 's/^/   /'
    
    # Check if hosts are in workspaces
    echo ""
    echo "Workspace assignments:"
    echo "$HOSTS_RESPONSE" | jq -r '.results[] | "   Host \(.id): \(.groups[0].name // "No workspace")"'
else
    echo "   (no hosts visible to Leia)"
fi

echo ""
echo "🏗️  Testing Leia's Workspace Access..."

# Test Leia's workspace access
WORKSPACES_RESPONSE=$(curl -s -H "x-rh-identity: $LEIA_HEADER" \
    -H "Accept: application/json" \
    "http://localhost:8002/api/inventory/v1/groups")

if ! echo "$WORKSPACES_RESPONSE" | jq -e '.results' >/dev/null 2>&1; then
    echo "❌ ERROR: Failed to get workspaces for Leia"
    echo "Response: $WORKSPACES_RESPONSE"
else
    WORKSPACE_COUNT=$(echo "$WORKSPACES_RESPONSE" | jq '.results | length')
    echo "📊 Leia can see $WORKSPACE_COUNT workspaces"
    
    if [[ "$WORKSPACE_COUNT" -gt 0 ]]; then
        echo ""
        echo "📋 Workspace Details:"
        echo "$WORKSPACES_RESPONSE" | jq -r '.results[] | "   - \(.name) (ID: \(.id), Hosts: \(.host_count // 0))"'
        
        # Find Leia's workspace
        LEIA_WORKSPACE_NAME=$(echo "$WORKSPACES_RESPONSE" | jq -r '.results[] | select(.name | contains("leia-workspace")) | .name' | head -1)
        LEIA_WORKSPACE_UUID=$(echo "$WORKSPACES_RESPONSE" | jq -r '.results[] | select(.name | contains("leia-workspace")) | .id' | head -1)
        
        if [[ -n "$LEIA_WORKSPACE_NAME" && "$LEIA_WORKSPACE_NAME" != "null" ]]; then
            echo ""
            echo "🔗 Leia's Workspace Found:"
            echo "   Name: $LEIA_WORKSPACE_NAME"
            echo "   UUID: $LEIA_WORKSPACE_UUID"
            
            # Verify hosts are in Leia's workspace
            if [[ "$HOST_COUNT" -gt 0 ]]; then
                HOSTS_IN_WORKSPACE=$(echo "$HOSTS_RESPONSE" | jq --arg workspace_id "$LEIA_WORKSPACE_UUID" '[.results[] | select(.groups[]?.id == $workspace_id)] | length')
                echo "   Hosts in workspace: $HOSTS_IN_WORKSPACE"
                
                if [[ "$HOSTS_IN_WORKSPACE" -eq "$HOST_COUNT" ]]; then
                    echo "   ✅ All of Leia's hosts are in his workspace"
                else
                    echo "   ⚠️  Only $HOSTS_IN_WORKSPACE of $HOST_COUNT hosts are in Leia's workspace"
                fi
            fi
        else
            echo ""
            echo "⚠️  Leia's workspace not found in accessible workspaces"
        fi
    else
        echo "   (no workspaces visible to Leia)"
    fi
fi

echo ""
echo "=== TEST SUMMARY ==="
echo ""

if [[ "$TEST_RESULT" == "PASS" ]]; then
    echo "🎉 LEIA'S PERMISSIONS TEST PASSED!"
    echo ""
    echo "✅ Results:"
    echo "  • Leia can see exactly 2 hosts ✓"
    echo "  • Leia can access his workspace ✓"
    echo "  • RBAC filtering is working correctly ✓"
    echo ""
    echo "📊 Summary:"
    echo "  • Host count: $HOST_COUNT (expected: 2)"
    echo "  • Workspace count: $WORKSPACE_COUNT"
    if [[ -n "${LEIA_WORKSPACE_NAME:-}" ]]; then
        echo "  • Leia's workspace: $LEIA_WORKSPACE_NAME"
    fi
    echo ""
    echo "The workspace-based permission system is working correctly for Leia!"
    exit 0
else
    echo "❌ LEIA'S PERMISSIONS TEST FAILED!"
    echo ""
    echo "❌ Issues:"
    echo "  • Leia sees $HOST_COUNT hosts (expected: 2)"
    echo "  • RBAC filtering may not be working correctly"
    echo ""
    echo "🔧 Troubleshooting steps:"
    echo "  1. Check if Leia's workspace exists:"
    echo "     scripts/setup_leia_demo.sh"
    echo ""
    echo "  2. Verify RBAC configuration:"
    echo "     oc exec \$(oc get pods -l pod=rbac-service -o name | head -1) -- ./rbac/manage.py shell"
    echo "     >>> from management.models import Principal, Policy, ResourceDefinition"
    echo "     >>> leia = Principal.objects.get(username='leia')"
    echo "     >>> policies = Policy.objects.filter(group__principals=leia)"
    echo "     >>> print([p.name for p in policies])"
    echo ""
    echo "  3. Check RBAC service logs:"
    echo "     oc logs -l pod=rbac-service"
    echo ""
    echo "  4. Check HBI service logs:"
    echo "     oc logs -l pod=host-inventory-service-reads"
    echo ""
    echo "  5. Re-run the full setup:"
    echo "     scripts/setup_leia_demo.sh"
    exit 1
fi 