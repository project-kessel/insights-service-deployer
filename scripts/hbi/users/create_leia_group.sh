#!/usr/bin/env bash

# Create Leia's Group and Permissions
# This script creates Leia's RBAC group, policy, and workspace restrictions

set -e

echo "🔧 Creating Leia's Group and Permissions"
echo "========================================"

# Get RBAC service pod
RBAC_POD=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)

if [[ -z "$RBAC_POD" ]]; then
    echo "❌ ERROR: Could not find RBAC service pod"
    exit 1
fi

echo "Using RBAC pod: $RBAC_POD"

# Function to setup port forwarding
setup_port_forward() {
    if ! curl -s --connect-timeout 2 http://localhost:8002/health >/dev/null 2>&1; then
        READS_POD=$(oc get pods -l pod=host-inventory-service-reads --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
        oc port-forward "$READS_POD" 8002:8000 >/tmp/pf_leia_group.log 2>&1 &
        PF_PID=$!
        sleep 3
        echo "$PF_PID" > /tmp/pf_leia_group.pid
    fi
}

cleanup_port_forward() {
    if [[ -f /tmp/pf_leia_group.pid ]]; then
        kill $(cat /tmp/pf_leia_group.pid) 2>/dev/null || true
        rm -f /tmp/pf_leia_group.pid /tmp/pf_leia_group.log
    fi
}
trap cleanup_port_forward EXIT

# Get Leia's workspace UUID
echo "📋 Getting Leia's workspace UUID..."
setup_port_forward

JDOE_JSON='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
JDOE_HEADER=$(echo -n "$JDOE_JSON" | base64 -w 0)

WORKSPACES_RESPONSE=$(curl -s -H "x-rh-identity: $JDOE_HEADER" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")

LEIA_WORKSPACE_UUID=$(echo "$WORKSPACES_RESPONSE" | jq -r '.results[] | select(.name | contains("leia-workspace")) | .id' | head -1)

if [[ -z "$LEIA_WORKSPACE_UUID" || "$LEIA_WORKSPACE_UUID" == "null" ]]; then
    echo "❌ ERROR: Could not find Leia's workspace"
    echo "Available workspaces:"
    echo "$WORKSPACES_RESPONSE" | jq -r '.results[] | "  - \(.name) (ID: \(.id))"'
    exit 1
fi

echo "Found Leia's workspace: $LEIA_WORKSPACE_UUID"

# Create Leia's group, policy, and permissions
CREATE_LEIA_GROUP_COMMAND="./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
from django.db import transaction
import json

try:
    with transaction.atomic():
        print('🔧 Creating Leia\\'s Group and Permissions...')
        
        # Get Leia
        leia_principal = Principal.objects.get(username='leia')
        print(f'Found Leia: {leia_principal.username} (ID: {leia_principal.user_id})')
        print(f'Leia tenant: {leia_principal.tenant}')
        
        # Remove Leia from any existing groups/policies
        existing_policies = Policy.objects.filter(group__principals=leia_principal)
        for policy in existing_policies:
            policy.group.principals.remove(leia_principal)
            print(f'Removed Leia from existing policy: {policy.name}')
        
        # Create Leia's group
        leia_group, created = Group.objects.get_or_create(
            name='leia-limited-group',
            defaults={
                'tenant': leia_principal.tenant,
                'description': 'Leia\\'s limited access group'
            }
        )
        
        if created:
            print(f'Created new group: {leia_group.name}')
        else:
            print(f'Found existing group: {leia_group.name}')
        
        # Add Leia to his group
        leia_group.principals.add(leia_principal)
        print(f'Added Leia to group: {leia_group.name}')
        
        # Create Leia's role
        leia_role, created = Role.objects.get_or_create(
            name='Leia Limited Viewer',
            defaults={
                'display_name': 'Leia Limited Viewer',
                'description': 'Leia\\'s limited viewer role',
                'system': False,
                'platform_default': False,
                'admin_default': False,
                'tenant': leia_principal.tenant
            }
        )
        
        if created:
            print(f'Created new role: {leia_role.name}')
        else:
            print(f'Found existing role: {leia_role.name}')
        
        # Add permissions to Leia's role (with proper tenant_id)
        inventory_permissions = ['inventory:hosts:read', 'inventory:groups:read']
        for perm_name in inventory_permissions:
            permission, created = Permission.objects.get_or_create(permission=perm_name)
            # Create Access object with explicit tenant_id
            access, created = Access.objects.get_or_create(
                role=leia_role, 
                permission=permission,
                defaults={'tenant': leia_principal.tenant}
            )
            if created:
                print(f'Added permission: {perm_name} (with tenant: {leia_principal.tenant})')
            else:
                # Update existing access to ensure it has tenant_id
                if not access.tenant:
                    access.tenant = leia_principal.tenant
                    access.save()
                    print(f'Updated permission tenant: {perm_name}')
        
        # Create Leia's policy
        leia_policy, created = Policy.objects.get_or_create(
            name='leia-limited-policy',
            defaults={
                'tenant': leia_principal.tenant,
                'description': 'Leia\\'s limited policy',
                'group': leia_group
            }
        )
        
        if created:
            print(f'Created new policy: {leia_policy.name}')
        else:
            print(f'Found existing policy: {leia_policy.name}')
            leia_policy.group = leia_group
            leia_policy.save()
        
        # Assign role to policy
        leia_policy.roles.add(leia_role)
        print(f'Assigned role {leia_role.name} to policy {leia_policy.name}')
        
        # Create ResourceDefinitions for workspace restriction
        leia_workspace_uuid = '$LEIA_WORKSPACE_UUID'
        print(f'Leia workspace UUID: {leia_workspace_uuid}')
        
        # Clear existing ResourceDefinitions for Leia's role
        access_objects = Access.objects.filter(role=leia_role)
        for access in access_objects:
            ResourceDefinition.objects.filter(access=access).delete()
        
        # Create new ResourceDefinitions
        rd_count = 0
        for access in access_objects:
            if access.permission.permission.startswith('inventory:'):
                rd = ResourceDefinition.objects.create(
                    access=access,
                    tenant=leia_principal.tenant,
                    attributeFilter={
                        'key': 'group.id',
                        'operation': 'in',
                        'value': [leia_workspace_uuid]
                    }
                )
                rd_count += 1
                print(f'Created ResourceDefinition: {access.permission.permission} -> {leia_workspace_uuid}')
        
        print(f'\\n✅ Successfully created Leia\\'s complete RBAC setup:')
        print(f'   • Group: {leia_group.name}')
        print(f'   • Role: {leia_role.name}')
        print(f'   • Policy: {leia_policy.name}')
        print(f'   • ResourceDefinitions: {rd_count}')
        print(f'   • Workspace restriction: {leia_workspace_uuid}')
        
        # Verify the setup
        print('\\n🔍 Verification:')
        groups = Group.objects.filter(principals=leia_principal)
        policies = Policy.objects.filter(group__principals=leia_principal)
        print(f'Leia is in {groups.count()} groups: {[g.name for g in groups]}')
        print(f'Leia has {policies.count()} policies: {[p.name for p in policies]}')
        
        for policy in policies:
            roles = policy.roles.all()
            print(f'Policy {policy.name} has roles: {[r.name for r in roles]}')
            for role in roles:
                access_objects = Access.objects.filter(role=role)
                for access in access_objects:
                    print(f'  Access: {access.permission.permission} (tenant: {access.tenant})')
                    rds = ResourceDefinition.objects.filter(access=access)
                    for rd in rds:
                        if rd.attributeFilter:
                            filter_value = rd.attributeFilter.get(\"value\", [])
                            print(f\"    ResourceDefinition: {filter_value}\")
                        else:
                            print(f\"    ResourceDefinition: No filter\")
        
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()

exit()
EOFPYTHON"

echo "🔧 Creating Leia's RBAC setup..."
if oc exec "$RBAC_POD" -- bash -c "$CREATE_LEIA_GROUP_COMMAND"; then
    echo "✅ Leia's group and permissions created successfully"
else
    echo "❌ Failed to create Leia's group and permissions"
    exit 1
fi

echo ""
echo "🎉 Leia's Group Setup Completed!"
echo "================================"
echo ""
echo "✅ Created:"
echo "  • Group: leia-limited-group"
echo "  • Role: Leia Limited Viewer"
echo "  • Policy: leia-limited-policy"
echo "  • ResourceDefinitions with workspace restriction"
echo ""
echo "🧪 Test Leia's access:"
echo "   ./scripts/test_leia_permissions.sh" 