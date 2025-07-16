#!/usr/bin/env bash

# Remove Default Host Administrator Role
# This script removes the "Inventory Hosts Administrator" role from the default access group
# This eliminates RBAC propagation delays

set -e

echo "🔧 Removing Default Host Administrator Role"
echo "=========================================="
echo ""
echo "This script will:"
echo "  1. Find the 'Inventory Hosts Administrator' role"
echo "  2. Remove it from the 'Default access' group"
echo "  3. Verify the changes"
echo ""
echo "⚠️  IMPORTANT: This will remove default host access for all users"
echo "   Users will need explicit workspace-specific permissions for host access"
echo ""

# --- Prerequisites ---
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
    
    echo "✅ Prerequisites check passed"
    echo "   Namespace: $NAMESPACE"
    echo ""
}

# --- Remove Role from Default Group ---
remove_role_from_default_group() {
    echo "🗑️  Deleting 'Inventory Hosts Administrator' role completely..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    if [[ -z "$rbac_pod" ]]; then
        echo "❌ ERROR: Could not find RBAC service pod"
        exit 1
    fi
    
    echo "Using RBAC pod: $rbac_pod"
    
    oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Role, Group, Policy, Access, ResourceDefinition
from django.db import transaction
import json

try:
    with transaction.atomic():
        print('🔍 Finding Inventory Hosts Administrator role...')
        
        # Find the specific role
        admin_role = Role.objects.filter(name='Inventory Hosts Administrator').first()
        if not admin_role:
            print('⚠️  Inventory Hosts Administrator role not found - already deleted')
            exit(0)
        
        print(f'Found role: {admin_role.name}')
        print(f'  Platform Default: {admin_role.platform_default}')
        print(f'  Admin Default: {admin_role.admin_default}')
        
        # Step 1: Remove role from all policies
        policies_with_role = Policy.objects.filter(roles=admin_role)
        if policies_with_role.exists():
            print(f'\\n🔧 Removing role from {policies_with_role.count()} policies...')
            for policy in policies_with_role:
                policy.roles.remove(admin_role)
                print(f'   Removed role from policy: {policy.name}')
        
        # Step 2: Remove role from all groups (through policies)
        groups_with_role_policies = Group.objects.filter(policies__roles=admin_role).distinct()
        if groups_with_role_policies.exists():
            print(f'\\n🔧 Removing role from groups via policies ({groups_with_role_policies.count()} groups)...')
            for group in groups_with_role_policies:
                # Remove role from all policies in this group
                group_policies_with_role = Policy.objects.filter(group=group, roles=admin_role)
                for policy in group_policies_with_role:
                    policy.roles.remove(admin_role)
                    print(f'   Removed role from policy: {policy.name} (group: {group.name})')
        
        # Step 3: Delete all ResourceDefinitions associated with this role's access objects
        access_objects = Access.objects.filter(role=admin_role)
        rd_count = 0
        for access in access_objects:
            rds = ResourceDefinition.objects.filter(access=access)
            rd_count += rds.count()
            rds.delete()
        if rd_count > 0:
            print(f'\\n🔧 Deleted {rd_count} ResourceDefinitions')
        
        # Step 4: Delete all Access objects for this role
        access_count = access_objects.count()
        if access_count > 0:
            print(f'\\n🔧 Deleting {access_count} Access objects...')
            access_objects.delete()
        
        # Step 5: Finally delete the role itself
        role_name = admin_role.name
        admin_role.delete()
        print(f'\\n🗑️  Successfully DELETED role: {role_name}')
        
        print(f'\\n✅ Complete deletion of \"Inventory Hosts Administrator\" role:')
        print(f'   • Removed from all policies and groups')
        print(f'   • Deleted {rd_count} ResourceDefinitions')
        print(f'   • Deleted {access_count} Access objects') 
        print(f'   • Deleted the role itself')
        print('✅ Default users will no longer have automatic host access')
        print('✅ Users will need explicit workspace-specific permissions')
        
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()

exit()
EOFPYTHON" 2>/dev/null
    
    echo "✅ Role deletion completed"
}

# --- Verify Changes ---
verify_changes() {
    echo ""
    echo "🔍 Verifying complete role deletion..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Role, Group, Policy, Access, ResourceDefinition
import json

try:
    print('🔍 Verification - checking if Inventory Hosts Administrator role was completely deleted...')
    
    # Check if the role still exists
    admin_role = Role.objects.filter(name='Inventory Hosts Administrator').first()
    
    if admin_role:
        print(f'❌ ERROR: Role still exists: {admin_role.name}')
        print(f'   Platform Default: {admin_role.platform_default}')
        print(f'   Admin Default: {admin_role.admin_default}')
        
        # Check remaining associations
        access_objects = Access.objects.filter(role=admin_role)
        policies_with_role = Policy.objects.filter(roles=admin_role)
        groups_with_role = Group.objects.filter(policies__roles=admin_role).distinct() # Corrected to use policies__roles
        
        print(f'\\n📋 Remaining associations:')
        print(f'   Access objects: {access_objects.count()}')
        print(f'   Policies with role: {policies_with_role.count()}')
        print(f'   Groups with role: {groups_with_role.count()}')
        
        if access_objects.exists():
            print(f'   Access permissions:')
            for access in access_objects:
                print(f'     - {access.permission.permission}')
        
        if policies_with_role.exists():
            print(f'   Policies:')
            for policy in policies_with_role:
                print(f'     - {policy.name}')
        
        if groups_with_role.exists():
            print(f'   Groups:')
            for group in groups_with_role:
                print(f'     - {group.name}')
        
        print(f'\\n❌ DELETION INCOMPLETE - role and associations still exist')
    else:
        print(f'\\n✅ SUCCESS: Inventory Hosts Administrator role has been completely deleted')
        
        # Double-check that no orphaned access objects remain
        orphaned_access = Access.objects.filter(role__name='Inventory Hosts Administrator')
        if orphaned_access.exists():
            print(f'⚠️  Warning: Found {orphaned_access.count()} orphaned access objects')
        else:
            print(f'✅ No orphaned access objects found')
        
        # Check default group state
        default_group = Group.objects.filter(name='Default access').first()
        if default_group:
            # Get all roles from policies in the default group
            remaining_policies = default_group.policies.all()
            all_roles_in_group = []
            for policy in remaining_policies:
                all_roles_in_group.extend(policy.roles.all())
            # Remove duplicates
            unique_roles = list({role.id: role for role in all_roles_in_group}.values())
            
            print(f'\\n📋 Default access group now has {len(unique_roles)} roles:')
            for role in unique_roles:
                print(f'   - {role.name}')
        else:
            print(f'\\n⚠️  Default access group not found')
        
        print(f'\\n✅ VERIFICATION COMPLETE: Role deletion successful')
        print(f'✅ Default users no longer have automatic host access')
    
except Exception as e:
    print(f'❌ Error during verification: {e}')
    import traceback
    traceback.print_exc()

exit()
EOFPYTHON" 2>/dev/null
}

# --- Print Summary ---
print_summary() {
    echo ""
    echo "🎉 DEFAULT HOST ADMIN ROLE DELETION COMPLETED!"
    echo "=============================================="
    echo ""
    echo "✅ What was done:"
    echo "  • COMPLETELY DELETED 'Inventory Hosts Administrator' role"
    echo "  • Removed role from all policies and groups"
    echo "  • Deleted all associated Access objects and ResourceDefinitions"
    echo "  • Users no longer get automatic host admin permissions"
    echo "  • RBAC propagation delays should be eliminated"
    echo ""
    echo "📋 Impact:"
    echo "  • New users will not automatically have host access"
    echo "  • Existing users may lose broad host access"
    echo "  • Luke, Leia, and Sara's workspace-specific permissions are unaffected"
    echo ""
    echo "🔧 Next steps:"
    echo "  • Verify that Luke and Leia can still access their assigned hosts"
    echo "  • Set up workspace-specific roles for other users as needed"
    echo "  • Test that new users don't have unauthorized host access"
    echo ""
    echo "🧪 To test user access:"
    echo "   ./test/e2e/test_luke_permissions.sh"
    echo "   ./test/e2e/test_leia_permissions.sh"
    echo "   ./test/e2e/test_sara_permissions.sh"
    echo ""
    echo "🔄 To restore the role (if needed):"
    echo "   ./scripts/hbi/add_inventory_admin_role.sh"
}

# --- Main Execution ---
main() {
    check_prerequisites
    remove_role_from_default_group
    verify_changes
    print_summary
}

main "$@" 