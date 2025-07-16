#!/usr/bin/env bash

# Test Alice's Permissions
# This script verifies that Alice can only see her assigned hosts and workspace

set -e

echo "🧪 Testing Alice's Permissions"
echo "=============================="
echo ""
echo "This script will verify that:"
echo "  • Alice can see exactly 4 hosts"
echo "  • Alice can only see her assigned workspace"
echo "  • Alice's hosts are in her workspace"
echo ""

# Setup port forwarding
setup_port_forwarding() {
    echo "🔧 Setting up port forwarding..."
    
    # Kill any existing port forwards
    pkill -f "oc port-forward.*8002" 2>/dev/null || true
    pkill -f "oc port-forward.*8003" 2>/dev/null || true
    sleep 2
    
    # Start port forward for host inventory service
    NAMESPACE=$(oc project -q)
    HBI_READ_POD=$(oc get pods -l pod=host-inventory-service-reads -o json | jq -r '.items[0].metadata.name')
    
    echo "📡 Starting port forward: localhost:8002 -> $HBI_READ_POD:8000"
    oc port-forward -n "$NAMESPACE" "$HBI_READ_POD" 8002:8000 >/dev/null 2>&1 &
    
    # Wait for port forward to be ready
    sleep 5
    
    echo "✅ Port forwarding established"
}

# Test Alice's host access
test_alice_host_access() {
    echo "🔍 Testing Alice's Host Access..."
    echo ""
    
    # Alice's identity header (based on rbac_users_data.json)
    local alice_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"alice","email":"alice@redhat.com","first_name":"Alice","last_name":"Team-A","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12347","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local alice_header
    alice_header=$(echo -n "$alice_json" | base64 -w 0)
    
    echo "📊 Getting hosts that Alice can see..."
    local alice_hosts_response
    alice_hosts_response=$(curl -s -H "x-rh-identity: $alice_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/hosts")
    
    local alice_host_count
    alice_host_count=$(echo "$alice_hosts_response" | jq -r '.total // 0')
    
    echo "📋 Alice can see $alice_host_count hosts"
    
    if [[ "$alice_host_count" -eq 4 ]]; then
        echo "✅ PASS: Alice sees exactly 4 hosts (as expected)"
        ALICE_HOST_ACCESS_TEST="PASS"
    else
        echo "❌ FAIL: Alice sees $alice_host_count hosts (expected 4)"
        echo "   This suggests RBAC filtering is not working correctly"
        ALICE_HOST_ACCESS_TEST="FAIL"
    fi
    
    # Get detailed host information
    echo ""
    echo "📋 Host Details:"
    echo "Host IDs Alice can see:"
    local alice_host_ids
    alice_host_ids=$(echo "$alice_hosts_response" | jq -r '.results[].id // empty')
    
    if [[ -n "$alice_host_ids" ]]; then
        echo "$alice_host_ids" | while read -r host_id; do
            echo "   $host_id"
        done
        
        # Check workspace assignments
        echo ""
        echo "Workspace assignments:"
        
        # Admin user for getting workspace details
        local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
        local jdoe_header
        jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
        
        local all_groups_response
        all_groups_response=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
        
        echo "$alice_host_ids" | while read -r host_id; do
            local host_workspace
            host_workspace=$(echo "$all_groups_response" | jq -r --arg host_id "$host_id" '.results[] | select(.host_ids[]? == $host_id) | .name // "Ungrouped Hosts"')
            echo "   Host $host_id: ${host_workspace:-Ungrouped Hosts}"
        done
    else
        echo "   No hosts visible to Alice"
    fi
}

# Test Alice's workspace access
test_alice_workspace_access() {
    echo ""
    echo "🏗️  Testing Alice's Workspace Access..."
    
    # Alice's identity header
    local alice_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"alice","email":"alice@redhat.com","first_name":"Alice","last_name":"Team-A","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12347","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local alice_header
    alice_header=$(echo -n "$alice_json" | base64 -w 0)
    
    local alice_groups_response
    alice_groups_response=$(curl -s -H "x-rh-identity: $alice_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
    
    local alice_workspace_count
    alice_workspace_count=$(echo "$alice_groups_response" | jq -r '.total // 0')
    
    echo "📊 Alice can see $alice_workspace_count workspaces"
    echo ""
    echo "📋 Workspace Details:"
    
    if [[ "$alice_workspace_count" -gt 0 ]]; then
        echo "$alice_groups_response" | jq -r '.results[] | "   - \(.name) (ID: \(.id), Hosts: \(.host_count // 0))"'
        
        # Find Alice's workspace
        local alice_workspace_name
        alice_workspace_name=$(echo "$alice_groups_response" | jq -r '.results[] | select(.name | contains("alice-workspace")) | .name' | head -1)
        
        if [[ -n "$alice_workspace_name" && "$alice_workspace_name" != "null" ]]; then
            local alice_workspace_uuid
            local alice_workspace_host_count
            alice_workspace_uuid=$(echo "$alice_groups_response" | jq -r --arg name "$alice_workspace_name" '.results[] | select(.name == $name) | .id')
            alice_workspace_host_count=$(echo "$alice_groups_response" | jq -r --arg name "$alice_workspace_name" '.results[] | select(.name == $name) | .host_count // 0')
            
            echo ""
            echo "🔗 Alice's Workspace Found:"
            echo "   Name: $alice_workspace_name"
            echo "   UUID: $alice_workspace_uuid"
            echo "   Hosts in workspace: $alice_workspace_host_count"
            
            if [[ "$alice_workspace_host_count" -eq 4 ]]; then
                echo "   ✅ Workspace has expected 4 hosts"
                ALICE_WORKSPACE_TEST="PASS"
            else
                echo "   ⚠️  Only $alice_workspace_host_count of 4 hosts are in Alice's workspace"
                ALICE_WORKSPACE_TEST="PARTIAL"
            fi
        else
            echo "   ❌ Alice's workspace not found"
            ALICE_WORKSPACE_TEST="FAIL"
        fi
    else
        echo "   No workspaces visible to Alice"
        ALICE_WORKSPACE_TEST="FAIL"
    fi
}

# Print test summary
print_test_summary() {
    echo ""
    echo "=== TEST SUMMARY ==="
    echo ""
    
    local overall_result="PASS"
    
    if [[ "$ALICE_HOST_ACCESS_TEST" == "PASS" ]]; then
        echo "✅ Host Access Test: PASSED"
    else
        echo "❌ Host Access Test: FAILED"
        overall_result="FAIL"
    fi
    
    if [[ "$ALICE_WORKSPACE_TEST" == "PASS" ]]; then
        echo "✅ Workspace Access Test: PASSED"
    else
        echo "❌ Workspace Access Test: FAILED"
        overall_result="FAIL"
    fi
    
    echo ""
    if [[ "$overall_result" == "PASS" ]]; then
        echo "🎉 ALICE'S PERMISSIONS TEST PASSED!"
        echo ""
        echo "✅ Alice correctly sees only her 4 assigned hosts"
        echo "✅ Alice can access her workspace"
        echo "✅ RBAC filtering is working correctly"
    else
        echo "❌ ALICE'S PERMISSIONS TEST FAILED!"
        echo ""
        echo "❌ Issues:"
        if [[ "$ALICE_HOST_ACCESS_TEST" == "FAIL" ]]; then
            echo "  • Alice sees incorrect number of hosts"
        fi
        if [[ "$ALICE_WORKSPACE_TEST" == "FAIL" ]]; then
            echo "  • Alice cannot access her workspace properly"
        fi
        echo ""
        echo "🔧 Troubleshooting steps:"
        echo "  1. Check if Alice's workspace exists:"
        echo "     scripts/hbi/users/setup_alice.sh"
        echo ""
        echo "  2. Verify RBAC configuration:"
        echo "     oc exec \$(oc get pods -l pod=rbac-service -o name | head -1) -- ./rbac/manage.py shell"
        echo "     >>> from management.models import Principal, Policy, ResourceDefinition"
        echo "     >>> alice = Principal.objects.get(username='alice')"
        echo "     >>> policies = Policy.objects.filter(group__principals=alice)"
        echo "     >>> print([p.name for p in policies])"
        echo ""
        echo "  3. Check RBAC service logs:"
        echo "     oc logs -l pod=rbac-service"
        echo ""
        echo "  4. Check HBI service logs:"
        echo "     oc logs -l pod=host-inventory-service-reads"
        echo ""
        echo "  5. Re-run the full setup:"
        echo "     scripts/hbi/users/setup_alice.sh"
    fi
}

# Cleanup port forwards
cleanup() {
    echo ""
    echo "🧹 Cleaning up port forwards..."
    pkill -f "oc port-forward.*8002" 2>/dev/null || true
}

# Main execution
main() {
    # Set up cleanup trap
    trap cleanup EXIT
    
    setup_port_forwarding
    test_alice_host_access
    test_alice_workspace_access
    print_test_summary
}

# Run main function
main "$@" 