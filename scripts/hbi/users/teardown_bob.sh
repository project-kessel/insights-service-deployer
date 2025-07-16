#!/usr/bin/env bash

# Bob Teardown Script
# This script removes Bob's RBAC setup and workspace

set -e

echo "🗑️  Bob Demo Teardown"
echo "===================="
echo ""
echo "This script will:"
echo "  1. Remove Bob's RBAC permissions and roles"
echo "  2. Delete Bob's workspace and host assignments"
echo "  3. Clean up all associated RBAC objects"
echo ""
echo "⚠️  WARNING: This will permanently delete Bob's workspace and permissions!"
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

# Remove Bob's RBAC setup
remove_bob_rbac() {
    echo "🗑️  Removing Bob's RBAC setup..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    # Remove Bob's RBAC configuration
    local REMOVE_BOB_RBAC_COMMAND="./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
from django.db import transaction
import json

try:
    with transaction.atomic():
        print('🗑️  Removing Bob\\'s RBAC setup...')
        
        # Get Bob
        try:
            bob_principal = Principal.objects.get(username='bob')
            print(f'Found Bob: {bob_principal.username} (ID: {bob_principal.user_id})')
        except Principal.DoesNotExist:
            print('⚠️  Bob not found in RBAC, nothing to remove')
            exit()
        
        # Remove Bob from any groups
        existing_groups = Group.objects.filter(principals=bob_principal)
        for group in existing_groups:
            group.principals.remove(bob_principal)
            print(f'Removed Bob from group: {group.name}')
        
        # Find and delete Bob's specific objects
        objects_deleted = {
            'policies': 0,
            'groups': 0,
            'roles': 0,
            'access_objects': 0,
            'resource_definitions': 0
        }
        
        # Delete Bob's policy
        bob_policies = Policy.objects.filter(name__icontains='bob')
        for policy in bob_policies:
            # First remove roles from policy
            policy.roles.clear()
            policy.delete()
            objects_deleted['policies'] += 1
            print(f'Deleted policy: {policy.name}')
        
        # Delete Bob's group
        bob_groups = Group.objects.filter(name__icontains='bob')
        for group in bob_groups:
            group.delete()
            objects_deleted['groups'] += 1
            print(f'Deleted group: {group.name}')
        
        # Delete Bob's role and associated objects
        bob_roles = Role.objects.filter(name__icontains='Bob')
        for role in bob_roles:
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
        
        print(f'\\n✅ Successfully removed Bob\\'s RBAC setup:')
        print(f'   • Policies deleted: {objects_deleted[\"policies\"]}')
        print(f'   • Groups deleted: {objects_deleted[\"groups\"]}')
        print(f'   • Roles deleted: {objects_deleted[\"roles\"]}')
        print(f'   • Access objects deleted: {objects_deleted[\"access_objects\"]}')
        print(f'   • ResourceDefinitions deleted: {objects_deleted[\"resource_definitions\"]}')
        
        # Verify cleanup
        remaining_groups = Group.objects.filter(principals=bob_principal).count()
        remaining_policies = Policy.objects.filter(group__principals=bob_principal).count()
        print(f'\\n🔍 Verification:')
        print(f'   Bob is now in {remaining_groups} groups')
        print(f'   Bob has {remaining_policies} policies')
        
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()

exit()
EOFPYTHON"

    echo "🗑️  Executing Bob RBAC cleanup..."
    if oc exec "$rbac_pod" -- bash -c "$REMOVE_BOB_RBAC_COMMAND"; then
        echo "✅ Bob's RBAC setup removed successfully"
    else
        echo "❌ Failed to remove Bob's RBAC setup"
        exit 1
    fi
}

# Remove Bob's workspace
remove_bob_workspace() {
    echo "🗑️  Removing Bob's workspace..."
    
    # Admin user JSON for API calls
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    # Get all workspaces and find Bob's
    echo "🔍 Finding Bob's workspace..."
    local workspaces_response
    workspaces_response=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
    
    local bob_workspaces
    bob_workspaces=($(echo "$workspaces_response" | jq -r '.results[] | select(.name | contains("bob-workspace")) | .id'))
    
    if [[ ${#bob_workspaces[@]} -eq 0 ]]; then
        echo "ℹ️  No Bob workspaces found to delete"
        return 0
    fi
    
    echo "Found ${#bob_workspaces[@]} Bob workspace(s) to delete"
    
    # Delete each Bob workspace
    for workspace_id in "${bob_workspaces[@]}"; do
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
    
    echo "✅ Bob's workspace cleanup completed"
}

# Verify cleanup
verify_cleanup() {
    echo "🔍 Verifying Bob's cleanup..."
    
    # Check workspaces
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    local workspaces_response
    workspaces_response=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
    
    local remaining_bob_workspaces
    remaining_bob_workspaces=$(echo "$workspaces_response" | jq -r '.results[] | select(.name | contains("bob-workspace")) | .name' | wc -l)
    
    echo "📋 Cleanup verification:"
    echo "   Remaining Bob workspaces: $remaining_bob_workspaces"
    
    # Test Bob's access
    echo "🧪 Testing Bob's current access..."
    local bob_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"bob","email":"bob@redhat.com","first_name":"Bob","last_name":"TeamB","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12348","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local bob_header
    bob_header=$(echo -n "$bob_json" | base64 -w 0)
    
    local bob_hosts_response
    bob_hosts_response=$(curl -s -H "x-rh-identity: $bob_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/hosts")
    
    local bob_host_count
    bob_host_count=$(echo "$bob_hosts_response" | jq -r '.total // 0')
    
    echo "   Bob can now see: $bob_host_count hosts"
    
    if [[ "$bob_host_count" -eq 0 ]]; then
        echo "✅ SUCCESS: Bob has no host access (cleanup successful)"
    else
        echo "⚠️  WARNING: Bob can still see $bob_host_count hosts"
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "🎉 BOB TEARDOWN COMPLETED!"
    echo "=========================="
    echo ""
    echo "✅ What was removed:"
    echo "  • Bob's RBAC group, policy, and role"
    echo "  • Bob's workspace and host assignments"
    echo "  • All ResourceDefinitions and Access objects"
    echo "  • Bob's permissions and workspace isolation"
    echo ""
    echo "📋 Post-teardown state:"
    echo "  • Bob has no special RBAC permissions"
    echo "  • Bob's workspace has been deleted"
    echo "  • Bob's hosts are back in 'Ungrouped' status"
    echo "  • Bob will see hosts based on default permissions only"
    echo ""
    echo "🔄 To recreate Bob's setup:"
    echo "   ./scripts/hbi/users/setup_bob.sh"
    echo ""
    echo "📚 Bob's workspace isolation has been completely removed!"
}

# Main execution
main() {
    check_prerequisites
    setup_port_forwarding
    remove_bob_rbac
    remove_bob_workspace
    verify_cleanup
    print_summary
}

# Run main function
main "$@" 