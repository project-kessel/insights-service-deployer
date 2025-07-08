#!/usr/bin/env bash

# Restore Default Host Admin - Script
# This script restores default host admin permissions to the 'Inventory Hosts Administrator' role.

set -e

echo "🔐 Restoring Default Host Admin Permissions"
echo "=========================================="
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

# Restore permissions
restore_permissions() {
    echo "🔧 Restoring permissions..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    if [[ -z "$rbac_pod" ]]; then
        echo "❌ ERROR: Could not find rbac-service pod"
        exit 1
    fi
    
    oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOF'
from management.models import Role, Permission, Access
from django.db import transaction

try:
    with transaction.atomic():
        role_name = 'Inventory Hosts Administrator'
        permissions_to_add = ['inventory:hosts:read', 'inventory:hosts:write']
        
        print(f'Finding role: {role_name}')
        role = Role.objects.get(name=role_name)
        
        for perm_name in permissions_to_add:
            permission, created = Permission.objects.get_or_create(permission=perm_name)
            access, created = Access.objects.get_or_create(role=role, permission=permission, defaults={'tenant': role.tenant})
            if created:
                print(f'  ✅ Added permission \"{perm_name}\" to role \"{role_name}\"')
            else:
                print(f'  ℹ️ Permission \"{perm_name}\" already exists on role \"{role_name}\"')
        
        print('\n✅ Successfully restored default host admin permissions.')

except Role.DoesNotExist:
    print(f'❌ ERROR: Role \"{role_name}\" not found.')
except Exception as e:
    print(f'❌ An error occurred: {e}')
    import traceback
    traceback.print_exc()

exit()
EOF"
}

# Main execution
main() {
    check_prerequisites
    restore_permissions
    
    echo ""
    echo "🎉 RESTORE COMPLETED!"
    echo "======================"
    echo ""
    echo "✅ The 'Inventory Hosts Administrator' role now has 'inventory:hosts:read' and 'inventory:hosts:write' permissions."
}

main "$@" 