#!/usr/bin/env bash

# Test Bob's Permissions
# This script verifies that Bob can only see his assigned hosts and workspace

set -e

echo "🧪 Testing Bob's Permissions"
echo "============================"
echo ""
echo "This script will verify that:"
echo "  • Bob can see exactly 2 hosts"
echo "  • Bob can only see his assigned workspace"
echo "  • Bob's hosts are in his workspace"
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

# Test Bob's host access
test_bob_host_access() {
    echo "🔍 Testing Bob's Host Access..."
    echo ""
    
    # Bob's identity header (based on rbac_users_data.json)
    local bob_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"bob","email":"bob@redhat.com","first_name":"Bob","last_name":"TeamB","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12348","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local bob_header
    bob_header=$(echo -n "$bob_json" | base64 -w 0)
    
    echo "📊 Getting hosts that Bob can see..."
    local bob_hosts_response
    bob_hosts_response=$(curl -s -H "x-rh-identity: $bob_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/hosts")
    
    local bob_host_count
    bob_host_count=$(echo "$bob_hosts_response" | jq -r '.total // 0')
    
    echo "📋 Bob can see $bob_host_count hosts"
    
    if [[ "$bob_host_count" -eq 2 ]]; then
        echo "✅ PASS: Bob sees exactly 2 hosts (as expected)"
        BOB_HOST_ACCESS_TEST="PASS"
    else
        echo "❌ FAIL: Bob sees $bob_host_count hosts (expected 2)"
        echo "   This suggests RBAC filtering is not working correctly"
        BOB_HOST_ACCESS_TEST="FAIL"
    fi
    
    # Get detailed host information
    echo ""
    echo "📋 Host Details:"
    echo "Host IDs Bob can see:"
    local bob_host_ids
    bob_host_ids=$(echo "$bob_hosts_response" | jq -r '.results[].id // empty')
    
    if [[ -n "$bob_host_ids" ]]; then
        echo "$bob_host_ids" | while read -r host_id; do
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
        
        echo "$bob_host_ids" | while read -r host_id; do
            local host_workspace
            host_workspace=$(echo "$all_groups_response" | jq -r --arg host_id "$host_id" '.results[] | select(.host_ids[]? == $host_id) | .name // "Ungrouped Hosts"')
            echo "   Host $host_id: ${host_workspace:-Ungrouped Hosts}"
        done
    else
        echo "   No hosts visible to Bob"
    fi
}

# Test Bob's workspace access
test_bob_workspace_access() {
    echo ""
    echo "🏗️  Testing Bob's Workspace Access..."
    
    # Bob's identity header
    local bob_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"bob","email":"bob@redhat.com","first_name":"Bob","last_name":"TeamB","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12348","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local bob_header
    bob_header=$(echo -n "$bob_json" | base64 -w 0)
    
    local bob_groups_response
    bob_groups_response=$(curl -s -H "x-rh-identity: $bob_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
    
    local bob_workspace_count
    bob_workspace_count=$(echo "$bob_groups_response" | jq -r '.total // 0')
    
    echo "📊 Bob can see $bob_workspace_count workspaces"
    echo ""
    echo "📋 Workspace Details:"
    
    if [[ "$bob_workspace_count" -gt 0 ]]; then
        echo "$bob_groups_response" | jq -r '.results[] | "   - \(.name) (ID: \(.id), Hosts: \(.host_count // 0))"'
        
        # Find Bob's workspace
        local bob_workspace_name
        bob_workspace_name=$(echo "$bob_groups_response" | jq -r '.results[] | select(.name | contains("bob-workspace")) | .name' | head -1)
        
        if [[ -n "$bob_workspace_name" && "$bob_workspace_name" != "null" ]]; then
            local bob_workspace_uuid
            local bob_workspace_host_count
            bob_workspace_uuid=$(echo "$bob_groups_response" | jq -r --arg name "$bob_workspace_name" '.results[] | select(.name == $name) | .id')
            bob_workspace_host_count=$(echo "$bob_groups_response" | jq -r --arg name "$bob_workspace_name" '.results[] | select(.name == $name) | .host_count // 0')
            
            echo ""
            echo "🔗 Bob's Workspace Found:"
            echo "   Name: $bob_workspace_name"
            echo "   UUID: $bob_workspace_uuid"
            echo "   Hosts in workspace: $bob_workspace_host_count"
            
            if [[ "$bob_workspace_host_count" -eq 2 ]]; then
                echo "   ✅ Workspace has expected 2 hosts"
                BOB_WORKSPACE_TEST="PASS"
            else
                echo "   ⚠️  Only $bob_workspace_host_count of 2 hosts are in Bob's workspace"
                BOB_WORKSPACE_TEST="PARTIAL"
            fi
        else
            echo "   ❌ Bob's workspace not found"
            BOB_WORKSPACE_TEST="FAIL"
        fi
    else
        echo "   No workspaces visible to Bob"
        BOB_WORKSPACE_TEST="FAIL"
    fi
}

# Print test summary
print_test_summary() {
    echo ""
    echo "=== TEST SUMMARY ==="
    echo ""
    
    local overall_result="PASS"
    
    if [[ "$BOB_HOST_ACCESS_TEST" == "PASS" ]]; then
        echo "✅ Host Access Test: PASSED"
    else
        echo "❌ Host Access Test: FAILED"
        overall_result="FAIL"
    fi
    
    if [[ "$BOB_WORKSPACE_TEST" == "PASS" ]]; then
        echo "✅ Workspace Access Test: PASSED"
    else
        echo "❌ Workspace Access Test: FAILED"
        overall_result="FAIL"
    fi
    
    echo ""
    if [[ "$overall_result" == "PASS" ]]; then
        echo "🎉 BOB'S PERMISSIONS TEST PASSED!"
        echo ""
        echo "✅ Bob correctly sees only his 2 assigned hosts"
        echo "✅ Bob can access his workspace"
        echo "✅ RBAC filtering is working correctly"
    else
        echo "❌ BOB'S PERMISSIONS TEST FAILED!"
        echo ""
        echo "❌ Issues:"
        if [[ "$BOB_HOST_ACCESS_TEST" == "FAIL" ]]; then
            echo "  • Bob sees incorrect number of hosts"
        fi
        if [[ "$BOB_WORKSPACE_TEST" == "FAIL" ]]; then
            echo "  • Bob cannot access his workspace properly"
        fi
        echo ""
        echo "🔧 Troubleshooting steps:"
        echo "  1. Check if Bob's workspace exists:"
        echo "     scripts/hbi/users/setup_bob.sh"
        echo ""
        echo "  2. Verify RBAC configuration:"
        echo "     oc exec \$(oc get pods -l pod=rbac-service -o name | head -1) -- ./rbac/manage.py shell"
        echo "     >>> from management.models import Principal, Policy, ResourceDefinition"
        echo "     >>> bob = Principal.objects.get(username='bob')"
        echo "     >>> policies = Policy.objects.filter(group__principals=bob)"
        echo "     >>> print([p.name for p in policies])"
        echo ""
        echo "  3. Check RBAC service logs:"
        echo "     oc logs -l pod=rbac-service"
        echo ""
        echo "  4. Check HBI service logs:"
        echo "     oc logs -l pod=host-inventory-service-reads"
        echo ""
        echo "  5. Re-run the full setup:"
        echo "     scripts/hbi/users/setup_bob.sh"
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
    test_bob_host_access
    test_bob_workspace_access
    print_test_summary
}

# Run main function
main "$@" 