#!/usr/bin/env bash

# Teardown Leia - Clean up all Leia's RBAC and workspace components
# This script removes Leia's user, group, role, policy, resource definitions, and workspace

set -e

echo "🧹 Tearing down Leia's setup"
echo "============================"
echo ""
echo "This script will remove:"
echo "  • Leia's RBAC user, group, role, policy, and resource definitions"
echo "  • Leia's workspace (hosts will be left as-is)"
echo "  • All Leia-related RBAC components"
echo ""

# --- Prerequisites ---
check_prerequisites() {
    echo "🔍 Checking prerequisites..."
    if ! oc whoami >/dev/null 2>&1; then
        echo "❌ ERROR: Not logged into OpenShift"; exit 1; fi
    NAMESPACE=$(oc project -q 2>/dev/null || echo "")
    if [[ -z "$NAMESPACE" ]]; then
        echo "❌ ERROR: No OpenShift namespace selected"; exit 1; fi
    if ! oc get pods -l pod=rbac-service --no-headers 2>/dev/null | grep -q Running; then
        echo "❌ ERROR: RBAC service not running"; exit 1; fi
    if ! oc get pods -l pod=host-inventory-service-reads --no-headers 2>/dev/null | grep -q Running; then
        echo "❌ ERROR: Host inventory service not running"; exit 1; fi
    echo "✅ Prerequisites check passed (namespace: $NAMESPACE)"
}

# --- Port Forwarding ---
setup_port_forward() {
    echo "🔧 Setting up port forwarding..."
    pkill -f "oc port-forward.*800[23]" 2>/dev/null || true; sleep 2
    local reads_pod writes_pod
    reads_pod=$(oc get pods -l pod=host-inventory-service-reads --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
    writes_pod=$(oc get pods -l pod=host-inventory-service-writes --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
    oc port-forward "$reads_pod" 8002:8000 >/dev/null 2>&1 &
    oc port-forward "$writes_pod" 8003:8000 >/dev/null 2>&1 &
    sleep 3
    echo "✅ Port forwarding established"
}
cleanup_port_forward() { pkill -f "oc port-forward.*800[23]" 2>/dev/null || true; }
trap cleanup_port_forward EXIT

# --- Find Leia's Workspaces ---
find_leia_workspaces() {
    echo "🔍 Finding Leia's workspaces..."
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    local jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    local workspaces_response=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
    
    if echo "$workspaces_response" | jq -e '.results' >/dev/null 2>&1; then
        LEIA_WORKSPACE_UUIDS=($(echo "$workspaces_response" | jq -r '.results[] | select(.name | contains("leia-workspace")) | .id'))
        LEIA_WORKSPACE_NAMES=($(echo "$workspaces_response" | jq -r '.results[] | select(.name | contains("leia-workspace")) | .name'))
        
        if [[ ${#LEIA_WORKSPACE_UUIDS[@]} -gt 0 ]]; then
            echo "✅ Found ${#LEIA_WORKSPACE_UUIDS[@]} Leia workspace(s):"
            for i in "${!LEIA_WORKSPACE_NAMES[@]}"; do
                echo "   - ${LEIA_WORKSPACE_NAMES[i]} (${LEIA_WORKSPACE_UUIDS[i]})"
            done
        else
            echo "⚠️  No Leia workspaces found"
        fi
    else
        echo "❌ ERROR: Failed to get workspaces from inventory service"
        LEIA_WORKSPACE_UUIDS=()
        LEIA_WORKSPACE_NAMES=()
    fi
}

# --- Delete Leia's Workspaces ---
delete_leia_workspaces() {
    if [[ ${#LEIA_WORKSPACE_UUIDS[@]} -eq 0 ]]; then
        echo "⚠️  No Leia workspaces to delete"
        return 0
    fi
    
    echo "🗑️  Deleting Leia's workspaces..."
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    local jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    for i in "${!LEIA_WORKSPACE_UUIDS[@]}"; do
        local workspace_uuid="${LEIA_WORKSPACE_UUIDS[i]}"
        local workspace_name="${LEIA_WORKSPACE_NAMES[i]}"
        
        echo "   Deleting workspace: $workspace_name ($workspace_uuid)"
        local delete_response=$(curl -s -X DELETE "http://localhost:8003/api/inventory/v1/groups/$workspace_uuid" \
            -H "x-rh-identity: $jdoe_header")
        
        # Check if deletion was successful (empty response or success message)
        if [[ -z "$delete_response" ]] || echo "$delete_response" | jq -e '.message' >/dev/null 2>&1; then
            echo "   ✅ Deleted workspace: $workspace_name"
        else
            echo "   ⚠️  Failed to delete workspace $workspace_name: $delete_response"
        fi
    done
    
    echo "✅ Workspace deletion completed"
}

# --- Clean up Leia's RBAC Components ---
cleanup_leia_rbac() {
    echo "🔐 Cleaning up Leia's RBAC components..."
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
from django.db import transaction
import json

try:
    with transaction.atomic():
        print('🧹 Cleaning up Leia RBAC components...')
        
        # Try to find Leia principal
        leia_principal = None
        try:
            leia_principal = Principal.objects.get(username='leia')
            print(f'Found Leia: {leia_principal.username} (ID: {leia_principal.user_id})')
        except Principal.DoesNotExist:
            print('⚠️  Leia user not found in RBAC')
        
        # Find all Leia-related components using pattern matching
        leia_groups = Group.objects.filter(name__icontains='leia')
        leia_roles = Role.objects.filter(name__icontains='leia')
        leia_policies = Policy.objects.filter(name__icontains='leia')
        
        print(f'\\n🔍 Found Leia-related components:')
        print(f'   Groups: {[g.name for g in leia_groups]}')
        print(f'   Roles: {[r.name for r in leia_roles]}')
        print(f'   Policies: {[p.name for p in leia_policies]}')
        
        components_deleted = 0
        
        # Remove Leia from all groups/policies first
        if leia_principal:
            all_policies = Policy.objects.filter(group__principals=leia_principal)
            for policy in all_policies:
                policy.group.principals.remove(leia_principal)
                print(f'Removed Leia from policy: {policy.name}')
            
            all_groups = Group.objects.filter(principals=leia_principal)
            for group in all_groups:
                group.principals.remove(leia_principal)
                print(f'Removed Leia from group: {group.name}')
        
        # Delete ResourceDefinitions via Leia's roles
        for leia_role in leia_roles:
            access_objects = Access.objects.filter(role=leia_role)
            rd_count = 0
            for access in access_objects:
                rd_count += ResourceDefinition.objects.filter(access=access).count()
                ResourceDefinition.objects.filter(access=access).delete()
            if rd_count > 0:
                print(f'Deleted {rd_count} ResourceDefinitions for role: {leia_role.name}')
                components_deleted += rd_count
        
        # Delete Leia's policies
        for leia_policy in leia_policies:
            policy_name = leia_policy.name
            leia_policy.delete()
            print(f'Deleted policy: {policy_name}')
            components_deleted += 1
        
        # Delete Leia's groups
        for leia_group in leia_groups:
            group_name = leia_group.name
            leia_group.delete()
            print(f'Deleted group: {group_name}')
            components_deleted += 1
        
        # Delete Leia's roles (this will cascade delete Access objects)
        for leia_role in leia_roles:
            role_name = leia_role.name
            # Use the correct relationship name - it might be 'access' or 'accesses'
            try:
                access_count = Access.objects.filter(role=leia_role).count()
                leia_role.delete()
                print(f'Deleted role: {role_name} (and {access_count} access objects)')
                components_deleted += 1 + access_count
            except Exception as e:
                print(f'Error deleting role {role_name}: {e}')
                # Try to delete anyway
                leia_role.delete()
                print(f'Deleted role: {role_name} (access count unknown)')
                components_deleted += 1
        
        # Delete Leia's principal
        if leia_principal:
            username = leia_principal.username
            leia_principal.delete()
            print(f'Deleted principal: {username}')
            components_deleted += 1
        
        print(f'\\n✅ RBAC cleanup completed: {components_deleted} components deleted')
        
        # Final verification - check if any Leia components remain
        remaining_groups = Group.objects.filter(name__icontains='leia')
        remaining_roles = Role.objects.filter(name__icontains='leia')
        remaining_policies = Policy.objects.filter(name__icontains='leia')
        remaining_principals = Principal.objects.filter(username='leia')
        
        remaining_components = []
        for g in remaining_groups:
            remaining_components.append(f'Group: {g.name}')
        for r in remaining_roles:
            remaining_components.append(f'Role: {r.name}')
        for p in remaining_policies:
            remaining_components.append(f'Policy: {p.name}')
        for pr in remaining_principals:
            remaining_components.append(f'Principal: {pr.username}')
        
        if remaining_components:
            print(f'⚠️  Warning: Some Leia components may still exist:')
            for component in remaining_components:
                print(f'     - {component}')
        else:
            print('✅ Verification: All Leia RBAC components successfully removed')
        
except Exception as e:
    print(f'❌ Error during RBAC cleanup: {e}')
    import traceback
    traceback.print_exc()

exit()
EOFPYTHON" 2>/dev/null
    
    echo "✅ RBAC cleanup completed"
}

# --- Print Summary ---
print_summary() {
    echo ""
    echo "🎉 LEIA TEARDOWN COMPLETED!"
    echo "==========================="
    echo ""
    echo "✅ What was removed:"
    echo "  • Leia's RBAC user (principal)"
    echo "  • All Leia-related RBAC groups"
    echo "  • All Leia-related RBAC roles"
    echo "  • All Leia-related RBAC policies"
    echo "  • Leia's resource definitions"
    if [[ ${#LEIA_WORKSPACE_UUIDS[@]} -gt 0 ]]; then
        echo "  • ${#LEIA_WORKSPACE_UUIDS[@]} Leia workspace(s)"
    fi
    echo ""
    echo "📋 Notes:"
    echo "  • Hosts that were in Leia's workspace are now unassigned"
    echo "  • No host data was deleted"
    echo "  • Leia user can no longer access the inventory system"
    echo ""
    echo "🔄 To recreate Leia's setup:"
    echo "   ./scripts/setup_leia.sh"
}

# --- Main ---
main() {
    check_prerequisites
    setup_port_forward
    find_leia_workspaces
    delete_leia_workspaces
    cleanup_leia_rbac
    print_summary
}

main "$@" 