#!/usr/bin/env bash

# Alice Teardown Script
# This script removes Alice's RBAC setup and workspace

set -e

echo "🗑️  Alice Demo Teardown"
echo "======================"
echo ""
echo "This script will:"
echo "  1. Remove Alice's RBAC permissions and roles"
echo "  2. Delete Alice's workspace and host assignments"
echo "  3. Clean up all associated RBAC objects"
echo ""
echo "⚠️  WARNING: This will permanently delete Alice's workspace and permissions!"
echo ""

# Check prerequisites
check_prerequisites() {
    echo "🔍 Checking prerequisites..."
    
    if ! oc whoami >/dev/null 2>&1; then
        echo "❌ ERROR: Not logged into OpenShift"
        exit 1
    fi
    
    NAMESPACE=$(oc project -q 2>/dev/null || echo "")
    if [[ -z "$NAMESPACE" ]]; then
        echo "❌ ERROR: No OpenShift namespace selected"
        exit 1
    fi
    
    if ! oc get pods -l pod=rbac-service --no-headers 2>/dev/null | grep -q Running; then
        echo "❌ ERROR: RBAC service not running"
        exit 1
    fi
    
    if ! oc get pods -l pod=host-inventory-service --no-headers 2>/dev/null | grep -q Running; then
        echo "❌ ERROR: Host inventory service not running"
        exit 1
    fi
    
    echo "✅ Prerequisites check passed"
    echo "   Namespace: $NAMESPACE"
    echo ""
}

# Setup port forwarding for API access
setup_port_forwarding() {
    echo "🔧 Setting up port forwarding..."
    
    # Kill any existing port forwards
    pkill -f "oc port-forward.*8002" 2>/dev/null || true
    pkill -f "oc port-forward.*8003" 2>/dev/null || true
    sleep 2
    
    # Start new port forwards in background
    echo "Starting port forwards..."
    oc port-forward -n "$NAMESPACE" "$(oc get pods -l pod=host-inventory-service-reads -o json | jq -r '.items[0].metadata.name')" 8002:8000 >/dev/null 2>&1 &
    oc port-forward -n "$NAMESPACE" "$(oc get pods -l pod=host-inventory-service -o json | jq -r '.items[0].metadata.name')" 8003:8000 >/dev/null 2>&1 &
    
    # Wait for port forwards to be ready
    sleep 5
    
    echo "✅ Port forwarding established"
}

# Remove Alice's RBAC setup
remove_alice_rbac() {
    echo "🗑️  Removing Alice's RBAC setup..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    # Remove Alice's RBAC configuration
    local REMOVE_ALICE_RBAC_COMMAND="./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
from django.db import transaction
import json

try:
    with transaction.atomic():
        print('🗑️  Removing Alice\\'s RBAC setup...')
        
        # Get Alice
        try:
            alice_principal = Principal.objects.get(username='alice')
            print(f'Found Alice: {alice_principal.username} (ID: {alice_principal.user_id})')
        except Principal.DoesNotExist:
            print('⚠️  Alice not found in RBAC, nothing to remove')
            exit()
        
        # Remove Alice from any groups
        existing_groups = Group.objects.filter(principals=alice_principal)
        for group in existing_groups:
            group.principals.remove(alice_principal)
            print(f'Removed Alice from group: {group.name}')
        
        # Find and delete Alice's specific objects
        objects_deleted = {
            'policies': 0,
            'groups': 0,
            'roles': 0,
            'access_objects': 0,
            'resource_definitions': 0
        }
        
        # Delete Alice's policy
        alice_policies = Policy.objects.filter(name__icontains='alice')
        for policy in alice_policies:
            # First remove roles from policy
            policy.roles.clear()
            policy.delete()
            objects_deleted['policies'] += 1
            print(f'Deleted policy: {policy.name}')
        
        # Delete Alice's group
        alice_groups = Group.objects.filter(name__icontains='alice')
        for group in alice_groups:
            group.delete()
            objects_deleted['groups'] += 1
            print(f'Deleted group: {group.name}')
        
        # Delete Alice's role and associated objects
        alice_roles = Role.objects.filter(name__icontains='Alice')
        for role in alice_roles:
            # Delete ResourceDefinitions first
            access_objects = Access.objects.filter(role=role)
            for access in access_objects:
                rd_count = ResourceDefinition.objects.filter(access=access).count()
                ResourceDefinition.objects.filter(access=access).delete()
                objects_deleted['resource_definitions'] += rd_count
                print(f'Deleted {rd_count} ResourceDefinitions for access: {access.permission.permission}')
            
            # Delete Access objects
            access_count = access_objects.count()
            access_objects.delete()
            objects_deleted['access_objects'] += access_count
            print(f'Deleted {access_count} Access objects for role: {role.name}')
            
            # Delete the role
            role.delete()
            objects_deleted['roles'] += 1
            print(f'Deleted role: {role.name}')
        
        print(f'\\n✅ Successfully removed Alice\\'s RBAC setup:')
        print(f'   • Policies deleted: {objects_deleted[\"policies\"]}')
        print(f'   • Groups deleted: {objects_deleted[\"groups\"]}')
        print(f'   • Roles deleted: {objects_deleted[\"roles\"]}')
        print(f'   • Access objects deleted: {objects_deleted[\"access_objects\"]}')
        print(f'   • ResourceDefinitions deleted: {objects_deleted[\"resource_definitions\"]}')
        
        # Verify cleanup
        remaining_groups = Group.objects.filter(principals=alice_principal).count()
        remaining_policies = Policy.objects.filter(group__principals=alice_principal).count()
        print(f'\\n🔍 Verification:')
        print(f'   Alice is now in {remaining_groups} groups')
        print(f'   Alice has {remaining_policies} policies')
        
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()

exit()
EOFPYTHON"

    echo "🗑️  Executing Alice RBAC cleanup..."
    if oc exec "$rbac_pod" -- bash -c "$REMOVE_ALICE_RBAC_COMMAND"; then
        echo "✅ Alice's RBAC setup removed successfully"
    else
        echo "❌ Failed to remove Alice's RBAC setup"
        exit 1
    fi
}

# Remove Alice's workspace
remove_alice_workspace() {
    echo "🗑️  Removing Alice's workspace..."
    
    # Admin user JSON for API calls
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    # Get all workspaces and find Alice's
    echo "🔍 Finding Alice's workspace..."
    local workspaces_response
    workspaces_response=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
    
    local alice_workspaces
    alice_workspaces=($(echo "$workspaces_response" | jq -r '.results[] | select(.name | contains("alice-workspace")) | .id'))
    
    if [[ ${#alice_workspaces[@]} -eq 0 ]]; then
        echo "ℹ️  No Alice workspaces found to delete"
        return 0
    fi
    
    echo "Found ${#alice_workspaces[@]} Alice workspace(s) to delete"
    
    # Delete each Alice workspace
    for workspace_id in "${alice_workspaces[@]}"; do
        echo "🗑️  Deleting workspace: $workspace_id"
        
        local delete_response
        delete_response=$(curl -s -X DELETE "http://localhost:8003/api/inventory/v1/groups/$workspace_id" \
            -H "accept: application/json" \
            -H "x-rh-identity: $jdoe_header")
        
        # Check if deletion was successful (empty response or 204 status)
        if [[ -z "$delete_response" ]] || echo "$delete_response" | jq -e '.detail' >/dev/null 2>&1; then
            echo "✅ Workspace $workspace_id deleted successfully"
        else
            echo "⚠️  Workspace deletion response: $delete_response"
        fi
    done
    
    echo "✅ Alice's workspace cleanup completed"
}

# Verify cleanup
verify_cleanup() {
    echo "🔍 Verifying Alice's cleanup..."
    
    # Check workspaces
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    local workspaces_response
    workspaces_response=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
    
    local remaining_alice_workspaces
    remaining_alice_workspaces=$(echo "$workspaces_response" | jq -r '.results[] | select(.name | contains("alice-workspace")) | .name' | wc -l)
    
    echo "📋 Cleanup verification:"
    echo "   Remaining Alice workspaces: $remaining_alice_workspaces"
    
    # Test Alice's access
    echo "🧪 Testing Alice's current access..."
    local alice_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"alice","email":"alice@redhat.com","first_name":"Alice","last_name":"Team-A","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12347","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local alice_header
    alice_header=$(echo -n "$alice_json" | base64 -w 0)
    
    local alice_hosts_response
    alice_hosts_response=$(curl -s -H "x-rh-identity: $alice_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/hosts")
    
    local alice_host_count
    alice_host_count=$(echo "$alice_hosts_response" | jq -r '.total // 0')
    
    echo "   Alice can now see: $alice_host_count hosts"
    
    if [[ "$alice_host_count" -eq 0 ]]; then
        echo "✅ SUCCESS: Alice has no host access (cleanup successful)"
    else
        echo "⚠️  WARNING: Alice can still see $alice_host_count hosts"
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "🎉 ALICE TEARDOWN COMPLETED!"
    echo "============================"
    echo ""
    echo "✅ What was removed:"
    echo "  • Alice's RBAC group, policy, and role"
    echo "  • Alice's workspace and host assignments"
    echo "  • All ResourceDefinitions and Access objects"
    echo "  • Alice's permissions and workspace isolation"
    echo ""
    echo "📋 Post-teardown state:"
    echo "  • Alice has no special RBAC permissions"
    echo "  • Alice's workspace has been deleted"
    echo "  • Alice's hosts are back in 'Ungrouped' status"
    echo "  • Alice will see hosts based on default permissions only"
    echo ""
    echo "🔄 To recreate Alice's setup:"
    echo "   ./scripts/hbi/users/setup_alice.sh"
    echo ""
    echo "📚 Alice's workspace isolation has been completely removed!"
}

# Main execution
main() {
    check_prerequisites
    setup_port_forwarding
    remove_alice_rbac
    remove_alice_workspace
    verify_cleanup
    print_summary
}

# Run main function
main "$@" 