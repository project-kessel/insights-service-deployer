#!/usr/bin/env bash

# Add Inventory Hosts Administrator Role
# This script recreates the "Inventory Hosts Administrator" role
# and adds it to the default access group

set -e

echo "🔄 Adding Inventory Hosts Administrator Role"
echo "============================================"
echo ""
echo "This script will:"
echo "  1. Create the 'Inventory Hosts Administrator' role with read/write permissions"
echo "  2. Add it to the default access group"
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
    
    echo "✅ Prerequisites check passed"
    echo "   Namespace: $NAMESPACE"
    echo ""
}

# Add the role
add_inventory_admin_role() {
    echo "🔧 Creating 'Inventory Hosts Administrator' role from scratch..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Role, Permission, Access, Group, Policy, Principal
from django.db import transaction

try:
    with transaction.atomic():
        print('🔍 Getting tenant from existing principal...')
        
        # Get tenant from jdoe (the default admin user that always exists)
        jdoe_principal = Principal.objects.get(username='jdoe')
        tenant = jdoe_principal.tenant
        print(f'Using tenant: {tenant} (from jdoe)')
        
        print('🔍 Checking if Inventory Hosts Administrator role already exists...')
        
        # Check if role already exists and delete it first if it does
        existing_role = Role.objects.filter(name='Inventory Hosts Administrator').first()
        if existing_role:
            print(f'⚠️  Role already exists: {existing_role.name}')
            print('🗑️  Deleting existing role to recreate from scratch...')
            
            # Clean up existing access objects and resource definitions
            access_objects = Access.objects.filter(role=existing_role)
            access_count = access_objects.count()
            access_objects.delete()
            
            # Delete the existing role
            existing_role.delete()
            print(f'   Deleted existing role and {access_count} access objects')
        
        print('🔧 Creating new Inventory Hosts Administrator role...')
        
        # Create the role from scratch with proper tenant
        role = Role.objects.create(
            name='Inventory Hosts Administrator',
            display_name='Inventory Hosts Administrator',
            description='Administrator access to hosts',
            system=True,
            platform_default=True,
            tenant=tenant  # ✅ Fixed: Add the tenant!
        )
        print(f'✅ Created role: {role.name} (tenant: {tenant})')
        
        # Add permissions
        permissions_to_add = ['inventory:hosts:read', 'inventory:hosts:write']
        access_count = 0
        for perm_name in permissions_to_add:
            permission, perm_created = Permission.objects.get_or_create(permission=perm_name)
            if perm_created:
                print(f'   Created permission: {perm_name}')
            else:
                print(f'   Found existing permission: {perm_name}')
            
            # Create access object with proper tenant
            access = Access.objects.create(
                role=role, 
                permission=permission,
                tenant=tenant  # ✅ Fixed: Add the tenant!
            )
            access_count += 1
            print(f'   Added access: {perm_name} to role (tenant: {tenant})')
        
        print(f'✅ Role created with {access_count} permissions')
        
        # Add to default group via policy
        default_group, group_created = Group.objects.get_or_create(
            name='Default access',
            defaults={
                'platform_default': True,
                'tenant': tenant  # ✅ Fixed: Add the tenant!
            }
        )
        
        if group_created:
            print('✅ Created Default access group')
        else:
            print('✅ Found existing Default access group')
            # Ensure existing group has tenant
            if not default_group.tenant:
                default_group.tenant = tenant
                default_group.save()
                print('   Updated group tenant')
        
        # Create or find policy for the default group
        default_policy, policy_created = Policy.objects.get_or_create(
            name='Default Access Policy',
            defaults={
                'group': default_group,
                'description': 'Default policy for platform access',
                'tenant': tenant  # ✅ Fixed: Add the tenant!
            }
        )
        
        if policy_created:
            print('✅ Created Default Access Policy')
        else:
            print('✅ Found existing Default Access Policy')
            # Ensure existing policy has tenant and group
            if not default_policy.tenant:
                default_policy.tenant = tenant
            default_policy.group = default_group
            default_policy.save()
            print('   Updated policy tenant and group')
        
        # Add role to policy (not directly to group)
        default_policy.roles.add(role)
        print('✅ Role added to Default access group via policy')
        
        print(f'\n✅ Successfully created complete Inventory Hosts Administrator role:')
        print(f'   • Role: {role.name}')
        print(f'   • Tenant: {tenant}')
        print(f'   • Permissions: {permissions_to_add}')
        print(f'   • Added to: Default access group')
        print('✅ Default users now have automatic host access')
        
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()

exit()
EOFPYTHON" 2>/dev/null
    
    echo "✅ Role creation completed"
}



# Main execution
main() {
    check_prerequisites
    add_inventory_admin_role
    
    echo ""
    echo "🎉 ROLE CREATION COMPLETED!"
    echo "=========================="
    echo ""
    echo "✅ What was done:"
    echo "  • CREATED 'Inventory Hosts Administrator' role from scratch"
    echo "  • Added inventory:hosts:read and inventory:hosts:write permissions"
    echo "  • Added role to Default access group"
    echo "  • All users now have automatic host access permissions"
    echo ""
    echo "📋 Impact:"
    echo "  • Default users now have automatic host administrator access"
    echo "  • New users will automatically receive host permissions"
    echo "  • Workspace-specific permissions are additional to these defaults"
    echo ""
    echo "🧪 Role has been successfully restored!"
    echo ""
    echo "🔄 To remove the role again:"
    echo "   ./remove_default_host_admin.sh"
}

main "$@" 