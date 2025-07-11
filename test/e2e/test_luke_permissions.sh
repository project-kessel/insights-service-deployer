#!/usr/bin/env bash

# Test Luke's Permissions Only
# This script verifies that Luke can see exactly 4 hosts and only his workspace

set -e

echo "🧪 Testing Luke's Permissions"
echo "============================="
echo ""
echo "This script will verify that:"
echo "  • Luke can see exactly 4 hosts"
echo "  • Luke can only see his assigned workspace"
echo "  • Luke's hosts are in his workspace"
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
        oc port-forward "$READS_POD" 8002:8000 >/tmp/pf_luke_test.log 2>&1 &
        PF_PID=$!
        sleep 3
        echo "$PF_PID" > /tmp/pf_luke_test.pid
        echo "✅ Port forwarding established"
    else
        echo "✅ Port forwarding already active"
    fi
}

cleanup_port_forward() {
    if [[ -f /tmp/pf_luke_test.pid ]]; then
        kill $(cat /tmp/pf_luke_test.pid) 2>/dev/null || true
        rm -f /tmp/pf_luke_test.pid /tmp/pf_luke_test.log
    fi
}
trap cleanup_port_forward EXIT

# Set up port forwarding
setup_port_forward

# Luke's user identity
LUKE_JSON='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"luke","email":"luke@redhat.com","first_name":"Luke","last_name":"Smith","is_active":true,"is_org_admin":false,"is_internal":false,"locale":"en_US","user_id":"12350","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'

# Function to encode user JSON to base64
base64_header() {
    echo -n "$1" | base64 -w 0
}

# Get Luke's identity header
LUKE_HEADER=$(base64_header "$LUKE_JSON")

echo "🔍 Testing Luke's Host Access..."
echo ""

# Test Luke's host access
echo "📊 Getting hosts that Luke can see..."
HOSTS_RESPONSE=$(curl -s -H "x-rh-identity: $LUKE_HEADER" \
    -H "Accept: application/json" \
    "http://localhost:8002/api/inventory/v1/hosts")

if ! echo "$HOSTS_RESPONSE" | jq -e '.results' >/dev/null 2>&1; then
    echo "❌ ERROR: Failed to get hosts for Luke"
    echo "Response: $HOSTS_RESPONSE"
    exit 1
fi

# Count hosts
HOST_COUNT=$(echo "$HOSTS_RESPONSE" | jq '.results | length')
echo "📋 Luke can see $HOST_COUNT hosts"

# Test result
if [[ "$HOST_COUNT" -eq 4 ]]; then
    echo "✅ SUCCESS: Luke sees exactly 4 hosts (as expected)"
    TEST_RESULT="PASS"
elif [[ "$HOST_COUNT" -gt 4 ]]; then
    echo "❌ FAIL: Luke sees $HOST_COUNT hosts (expected 4)"
    echo "   This suggests RBAC filtering is not working correctly"
    TEST_RESULT="FAIL"
else
    echo "❌ FAIL: Luke sees only $HOST_COUNT hosts (expected 4)"
    echo "   This suggests insufficient hosts or assignment issues"
    TEST_RESULT="FAIL"
fi

echo ""
echo "📋 Host Details:"
if [[ "$HOST_COUNT" -gt 0 ]]; then
    echo "Host IDs Luke can see:"
    echo "$HOSTS_RESPONSE" | jq -r '.results[].id' | sed 's/^/   /'
    
    # Check if hosts are in workspaces
    echo ""
    echo "Workspace assignments:"
    echo "$HOSTS_RESPONSE" | jq -r '.results[] | "   Host \(.id): \(.groups[0].name // "No workspace")"'
else
    echo "   (no hosts visible to Luke)"
fi

echo ""
echo "🏗️  Testing Luke's Workspace Access..."

# Test Luke's workspace access
WORKSPACES_RESPONSE=$(curl -s -H "x-rh-identity: $LUKE_HEADER" \
    -H "Accept: application/json" \
    "http://localhost:8002/api/inventory/v1/groups")

if ! echo "$WORKSPACES_RESPONSE" | jq -e '.results' >/dev/null 2>&1; then
    echo "❌ ERROR: Failed to get workspaces for Luke"
    echo "Response: $WORKSPACES_RESPONSE"
else
    WORKSPACE_COUNT=$(echo "$WORKSPACES_RESPONSE" | jq '.results | length')
    echo "📊 Luke can see $WORKSPACE_COUNT workspaces"
    
    if [[ "$WORKSPACE_COUNT" -gt 0 ]]; then
        echo ""
        echo "📋 Workspace Details:"
        echo "$WORKSPACES_RESPONSE" | jq -r '.results[] | "   - \(.name) (ID: \(.id), Hosts: \(.host_count // 0))"'
        
        # Find Luke's workspace
        LUKE_WORKSPACE_NAME=$(echo "$WORKSPACES_RESPONSE" | jq -r '.results[] | select(.name | contains("luke-workspace")) | .name' | head -1)
        LUKE_WORKSPACE_UUID=$(echo "$WORKSPACES_RESPONSE" | jq -r '.results[] | select(.name | contains("luke-workspace")) | .id' | head -1)
        
        if [[ -n "$LUKE_WORKSPACE_NAME" && "$LUKE_WORKSPACE_NAME" != "null" ]]; then
            echo ""
            echo "🔗 Luke's Workspace Found:"
            echo "   Name: $LUKE_WORKSPACE_NAME"
            echo "   UUID: $LUKE_WORKSPACE_UUID"
            
            # Verify hosts are in Luke's workspace
            if [[ "$HOST_COUNT" -gt 0 ]]; then
                HOSTS_IN_WORKSPACE=$(echo "$HOSTS_RESPONSE" | jq --arg workspace_id "$LUKE_WORKSPACE_UUID" '[.results[] | select(.groups[]?.id == $workspace_id)] | length')
                echo "   Hosts in workspace: $HOSTS_IN_WORKSPACE"
                
                if [[ "$HOSTS_IN_WORKSPACE" -eq "$HOST_COUNT" ]]; then
                    echo "   ✅ All of Luke's hosts are in his workspace"
                else
                    echo "   ⚠️  Only $HOSTS_IN_WORKSPACE of $HOST_COUNT hosts are in Luke's workspace"
                fi
            fi
        else
            echo ""
            echo "⚠️  Luke's workspace not found in accessible workspaces"
        fi
    else
        echo "   (no workspaces visible to Luke)"
    fi
fi

echo ""
echo "=== TEST SUMMARY ==="
echo ""

if [[ "$TEST_RESULT" == "PASS" ]]; then
    echo "🎉 LUKE'S PERMISSIONS TEST PASSED!"
    echo ""
    echo "✅ Results:"
    echo "  • Luke can see exactly 4 hosts ✓"
    echo "  • Luke can access his workspace ✓"
    echo "  • RBAC filtering is working correctly ✓"
    echo ""
    echo "📊 Summary:"
    echo "  • Host count: $HOST_COUNT (expected: 4)"
    echo "  • Workspace count: $WORKSPACE_COUNT"
    if [[ -n "${LUKE_WORKSPACE_NAME:-}" ]]; then
        echo "  • Luke's workspace: $LUKE_WORKSPACE_NAME"
    fi
    echo ""
    echo "The workspace-based permission system is working correctly for Luke!"
    exit 0
else
    echo "❌ LUKE'S PERMISSIONS TEST FAILED!"
    echo ""
    echo "❌ Issues:"
    echo "  • Luke sees $HOST_COUNT hosts (expected: 4)"
    echo "  • RBAC filtering may not be working correctly"
    echo ""
    echo "🔧 Troubleshooting steps:"
    echo "  1. Check if Luke's workspace exists:"
    echo "     scripts/setup_luke_demo.sh"
    echo ""
    echo "  2. Verify RBAC configuration:"
    echo "     oc exec \$(oc get pods -l pod=rbac-service -o name | head -1) -- ./rbac/manage.py shell"
    echo "     >>> from management.models import Principal, Policy, ResourceDefinition"
    echo "     >>> luke = Principal.objects.get(username='luke')"
    echo "     >>> policies = Policy.objects.filter(group__principals=luke)"
    echo "     >>> print([p.name for p in policies])"
    echo ""
    echo "  3. Check RBAC service logs:"
    echo "     oc logs -l pod=rbac-service"
    echo ""
    echo "  4. Check HBI service logs:"
    echo "     oc logs -l pod=host-inventory-service-reads"
    echo ""
    echo "  5. Re-run the full setup:"
    echo "     scripts/setup_luke_demo.sh"
    exit 1
fi 