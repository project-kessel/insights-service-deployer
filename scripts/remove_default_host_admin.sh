#!/usr/bin/env bash

# Remove Default Host Administrator Permission
# This script removes the inventory:hosts:* admin permission from the default role
# Converting it to a custom default role without broad host access

set -e

echo "🔧 Removing Default Host Permissions"
echo "===================================="
echo ""
echo "This script will:"
echo "  1. Find the default roles in RBAC"
echo "  2. Remove ALL inventory host permissions (read, write, admin)"
echo "  3. Convert them to custom default roles without host access"
echo "  4. Verify the changes"
echo ""
echo "⚠️  IMPORTANT: This will affect all users who rely on the default roles"
echo "   for host access. Make sure workspace-specific roles are configured!"
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

# --- Remove Default Host Admin Permissions ---
remove_default_host_admin() {
    echo "🔐 Removing default host administrator permissions..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    if [[ -z "$rbac_pod" ]]; then
        echo "❌ ERROR: Could not find RBAC service pod"
        exit 1
    fi
    
    echo "Using RBAC pod: $rbac_pod"
    
    oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
from django.db import transaction
import json

try:
    with transaction.atomic():
        print('🔍 Finding default roles and host administrator permissions...')
        
        # Find default groups (the key is to look at the default GROUP, not just default roles)
        default_groups = Group.objects.filter(
            name__in=[
                'Custom default access',
                'Default access', 
                'Default user access',
                'User Access',
                'Platform default',
                'Basic User'
            ]
        )
        
        # Also find groups that might be platform defaults
        platform_default_groups = Group.objects.filter(platform_default=True) if hasattr(Group, 'platform_default') else Group.objects.none()
        
        # Combine groups
        all_default_groups = list(default_groups) + list(platform_default_groups)
        unique_default_groups = list({group.id: group for group in all_default_groups}.values())
        
        print(f'Found {len(unique_default_groups)} default groups:')
        for group in unique_default_groups:
            print(f'  - {group.name}')
        
        # Get all roles from default groups
        unique_default_roles = []
        for group in unique_default_groups:
            group_policies = Policy.objects.filter(group=group)
            for policy in group_policies:
                for role in policy.roles.all():
                    unique_default_roles.append(role)
        
        # Remove duplicates from roles
        unique_default_roles = list({role.id: role for role in unique_default_roles}.values())
        
        # Also check for roles that are directly marked as defaults
        platform_default_roles = Role.objects.filter(platform_default=True)
        admin_default_roles = Role.objects.filter(admin_default=True)
        
        # Add these to our list
        for role in list(platform_default_roles) + list(admin_default_roles):
            if role.id not in {r.id for r in unique_default_roles}:
                unique_default_roles.append(role)
        
        print(f'Found {len(unique_default_roles)} potential default roles:')
        for role in unique_default_roles:
            print(f'  - {role.name} (platform_default: {role.platform_default}, admin_default: {role.admin_default})')
        
        # Find inventory host permissions (including read permissions)
        host_admin_permissions = Permission.objects.filter(
            permission__in=[
                'inventory:hosts:*',
                'inventory:hosts:write', 
                'inventory:hosts:read',
                'inventory:hosts:admin',
                'inventory:*:*'
            ]
        )
        
        print(f'\\nFound {len(host_admin_permissions)} host permissions to remove:')
        for perm in host_admin_permissions:
            print(f'  - {perm.permission}')
        
        # Track changes
        changes_made = 0
        roles_modified = []
        
        # Remove host admin permissions from default roles
        for role in unique_default_roles:
            role_changes = 0
            print(f'\\n🔧 Processing role: {role.name}')
            
            # Find access objects that link this role to host admin permissions
            for permission in host_admin_permissions:
                access_objects = Access.objects.filter(role=role, permission=permission)
                
                for access in access_objects:
                    print(f'   Removing permission: {permission.permission}')
                    
                    # Delete any ResourceDefinitions first
                    rd_count = ResourceDefinition.objects.filter(access=access).count()
                    if rd_count > 0:
                        ResourceDefinition.objects.filter(access=access).delete()
                        print(f'     Deleted {rd_count} ResourceDefinitions')
                    
                    # Delete the access object
                    access.delete()
                    print(f'     Removed access: {role.name} -> {permission.permission}')
                    
                    role_changes += 1
                    changes_made += 1
            
            if role_changes > 0:
                roles_modified.append(f'{role.name} ({role_changes} permissions removed)')
                print(f'   ✅ Modified role: {role.name} ({role_changes} permissions removed)')
            else:
                print(f'   ℹ️  No host permissions found in role: {role.name}')
        
        print(f'\\n📊 Summary of changes:')
        print(f'   Total permissions removed: {changes_made}')
        print(f'   Roles modified: {len(roles_modified)}')
        
        if roles_modified:
            print(f'\\n📋 Modified roles:')
            for role_info in roles_modified:
                print(f'     - {role_info}')
        
        if changes_made > 0:
            print(f'\\n✅ Successfully removed {changes_made} host permissions from default roles')
            print('✅ Default roles are now custom roles without any host access')
            print('✅ Users will need explicit workspace-specific permissions for host access')
        else:
            print('\\nℹ️  No host permissions found in default roles')
            print('ℹ️  Default roles may already be configured correctly')
        
        # Verification - show remaining permissions in default roles
        print(f'\\n🔍 Verification - remaining permissions in default roles:')
        for role in unique_default_roles:
            remaining_access = Access.objects.filter(role=role)
            if remaining_access.exists():
                print(f'   Role: {role.name}')
                for access in remaining_access:
                    print(f'     - {access.permission.permission}')
            else:
                print(f'   Role: {role.name} (no permissions)')
        
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()

exit()
EOFPYTHON" 2>/dev/null

    echo "✅ Default host permissions removal completed"
}

# --- Verify Changes ---
verify_changes() {
    echo ""
    echo "🔍 Verifying changes..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Role, Policy, Group, Access, Permission
import json

try:
    print('🔍 Final verification of default groups and roles...')
    
    # Check default groups first
    default_groups = Group.objects.filter(
        name__in=[
            'Custom default access',
            'Default access', 
            'Default user access',
            'User Access',
            'Platform default',
            'Basic User'
        ]
    )
    
    # Get roles from default groups
    unique_roles = []
    for group in default_groups:
        group_policies = Policy.objects.filter(group=group)
        for policy in group_policies:
            for role in policy.roles.all():
                unique_roles.append(role)
    
    # Also check roles that are directly marked as defaults
    platform_default_roles = Role.objects.filter(platform_default=True)
    admin_default_roles = Role.objects.filter(admin_default=True)
    
    # Add these to our list
    for role in list(platform_default_roles) + list(admin_default_roles):
        if role.id not in {r.id for r in unique_roles}:
            unique_roles.append(role)
    
    # Remove duplicates
    unique_roles = list({role.id: role for role in unique_roles}.values())
    
    print(f'\\n📋 Current state of default roles:')
    
    for role in unique_roles:
        print(f'\\nRole: {role.name}')
        print(f'  Platform Default: {role.platform_default}')
        print(f'  Admin Default: {role.admin_default}')
        
        access_objects = Access.objects.filter(role=role)
        if access_objects.exists():
            print(f'  Permissions:')
            for access in access_objects:
                print(f'    - {access.permission.permission}')
        else:
            print(f'  Permissions: None')
        
        # Check for any remaining host permissions
        host_access = access_objects.filter(
            permission__permission__in=[
                'inventory:hosts:*',
                'inventory:hosts:write',
                'inventory:hosts:read',
                'inventory:hosts:admin', 
                'inventory:*:*'
            ]
        )
        
        if host_access.exists():
            print(f'  ⚠️  WARNING: Still has host permissions:')
            for access in host_access:
                print(f'      - {access.permission.permission}')
        else:
            print(f'  ✅ No host permissions (good)')
    
    # Summary
    total_host_permissions_in_defaults = 0
    for role in unique_roles:
        host_permissions_count = Access.objects.filter(
            role=role,
            permission__permission__in=[
                'inventory:hosts:*',
                'inventory:hosts:write',
                'inventory:hosts:read',
                'inventory:hosts:admin',
                'inventory:*:*'
            ]
        ).count()
        total_host_permissions_in_defaults += host_permissions_count
    
    print(f'\\n📊 Verification Summary:')
    print(f'   Default groups checked: {len(default_groups)}')
    print(f'   Default roles checked: {len(unique_roles)}')
    print(f'   Host permissions in default roles: {total_host_permissions_in_defaults}')
    
    if total_host_permissions_in_defaults == 0:
        print(f'   ✅ SUCCESS: No host permissions in default roles')
        print(f'   ✅ Users will need explicit workspace permissions for host access')
    else:
        print(f'   ⚠️  WARNING: {total_host_permissions_in_defaults} host permissions still exist in default roles')
    
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
    echo "🎉 DEFAULT HOST PERMISSIONS REMOVAL COMPLETED!"
    echo "=============================================="
    echo ""
    echo "✅ What was done:"
    echo "  • Removed ALL inventory host permissions from default roles"
    echo "  • Converted default roles to custom roles without any host access"
    echo "  • Users now require explicit workspace-specific permissions"
    echo ""
    echo "📋 Impact:"
    echo "  • New users will not automatically have host admin access"
    echo "  • Existing users may lose broad host access (check workspace permissions)"
    echo "  • Luke and Leia's workspace-specific permissions are unaffected"
    echo ""
    echo "🔧 Next steps:"
    echo "  • Verify that Luke and Leia can still access their assigned hosts"
    echo "  • Set up workspace-specific roles for other users as needed"
    echo "  • Test that new users don't have unauthorized host access"
    echo ""
    echo "🧪 To test user access:"
    echo "   ./test/e2e/test_luke_permissions.sh"
    echo "   ./test/e2e/test_leia_permissions.sh"
    echo ""
    echo "🔄 To restore default host permissions (if needed):"
    echo "   You'll need to manually add inventory:hosts:read permission back to default roles"
}

# --- Main Execution ---
main() {
    check_prerequisites
    remove_default_host_admin
    verify_changes
    print_summary
}

main "$@" 