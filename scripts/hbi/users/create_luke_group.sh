#!/usr/bin/env bash

# Create Luke's Group and Permissions
# This script creates Luke's RBAC group, policy, and workspace restrictions

set -e

echo "🔧 Creating Luke's Group and Permissions"
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
        oc port-forward "$READS_POD" 8002:8000 >/tmp/pf_luke_group.log 2>&1 &
        PF_PID=$!
        sleep 3
        echo "$PF_PID" > /tmp/pf_luke_group.pid
    fi
}

cleanup_port_forward() {
    if [[ -f /tmp/pf_luke_group.pid ]]; then
        kill $(cat /tmp/pf_luke_group.pid) 2>/dev/null || true
        rm -f /tmp/pf_luke_group.pid /tmp/pf_luke_group.log
    fi
}
trap cleanup_port_forward EXIT

# Get Luke's workspace UUID
echo "📋 Getting Luke's workspace UUID..."
setup_port_forward

JDOE_JSON='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
JDOE_HEADER=$(echo -n "$JDOE_JSON" | base64 -w 0)

WORKSPACES_RESPONSE=$(curl -s -H "x-rh-identity: $JDOE_HEADER" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")

LUKE_WORKSPACE_UUID=$(echo "$WORKSPACES_RESPONSE" | jq -r '.results[] | select(.name | contains("luke-workspace")) | .id' | head -1)

if [[ -z "$LUKE_WORKSPACE_UUID" || "$LUKE_WORKSPACE_UUID" == "null" ]]; then
    echo "❌ ERROR: Could not find Luke's workspace"
    echo "Available workspaces:"
    echo "$WORKSPACES_RESPONSE" | jq -r '.results[] | "  - \(.name) (ID: \(.id))"'
    exit 1
fi

echo "Found Luke's workspace: $LUKE_WORKSPACE_UUID"

# Create Luke's group, policy, and permissions
CREATE_LUKE_GROUP_COMMAND="./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
from django.db import transaction
import json

try:
    with transaction.atomic():
        print('🔧 Creating Luke\\'s Group and Permissions...')
        
        # Get Luke
        luke_principal = Principal.objects.get(username='luke')
        print(f'Found Luke: {luke_principal.username} (ID: {luke_principal.user_id})')
        print(f'Luke tenant: {luke_principal.tenant}')
        
        # Remove Luke from any existing groups/policies
        existing_policies = Policy.objects.filter(group__principals=luke_principal)
        for policy in existing_policies:
            policy.group.principals.remove(luke_principal)
            print(f'Removed Luke from existing policy: {policy.name}')
        
        # Create Luke's group
        luke_group, created = Group.objects.get_or_create(
            name='luke-limited-group',
            defaults={
                'tenant': luke_principal.tenant,
                'description': 'Luke\\'s limited access group'
            }
        )
        
        if created:
            print(f'Created new group: {luke_group.name}')
        else:
            print(f'Found existing group: {luke_group.name}')
        
        # Add Luke to his group
        luke_group.principals.add(luke_principal)
        print(f'Added Luke to group: {luke_group.name}')
        
        # Create Luke's role
        luke_role, created = Role.objects.get_or_create(
            name='Luke Limited Viewer',
            defaults={
                'display_name': 'Luke Limited Viewer',
                'description': 'Luke\\'s limited viewer role',
                'system': False,
                'platform_default': False,
                'admin_default': False,
                'tenant': luke_principal.tenant
            }
        )
        
        if created:
            print(f'Created new role: {luke_role.name}')
        else:
            print(f'Found existing role: {luke_role.name}')
        
        # Add permissions to Luke's role (with proper tenant_id)
        inventory_permissions = ['inventory:hosts:read', 'inventory:groups:read']
        for perm_name in inventory_permissions:
            permission, created = Permission.objects.get_or_create(permission=perm_name)
            # Create Access object with explicit tenant_id
            access, created = Access.objects.get_or_create(
                role=luke_role,
                permission=permission,
                defaults={'tenant': luke_principal.tenant}
            )
            if created:
                print(f'Added permission: {perm_name} (with tenant: {luke_principal.tenant})')
            else:
                # Update existing access to ensure it has tenant_id
                if not access.tenant:
                    access.tenant = luke_principal.tenant
                    access.save()
                    print(f'Updated permission tenant: {perm_name}')
        
        # Create Luke's policy
        luke_policy, created = Policy.objects.get_or_create(
            name='luke-limited-policy',
            defaults={
                'tenant': luke_principal.tenant,
                'description': 'Luke\\'s limited policy',
                'group': luke_group
            }
        )
        
        if created:
            print(f'Created new policy: {luke_policy.name}')
        else:
            print(f'Found existing policy: {luke_policy.name}')
            luke_policy.group = luke_group
            luke_policy.save()
        
        # Assign role to policy
        luke_policy.roles.add(luke_role)
        print(f'Assigned role {luke_role.name} to policy {luke_policy.name}')
        
        # Create ResourceDefinitions for workspace restriction
        luke_workspace_uuid = '$LUKE_WORKSPACE_UUID'
        print(f'Luke workspace UUID: {luke_workspace_uuid}')
        
        # Clear existing ResourceDefinitions for Luke's role
        access_objects = Access.objects.filter(role=luke_role)
        for access in access_objects:
            ResourceDefinition.objects.filter(access=access).delete()
        
        # Create new ResourceDefinitions
        rd_count = 0
        for access in access_objects:
            if access.permission.permission.startswith('inventory:'):
                rd = ResourceDefinition.objects.create(
                    access=access,
                    tenant=luke_principal.tenant,
                    attributeFilter={
                        'key': 'group.id',
                        'operation': 'in',
                        'value': [luke_workspace_uuid]
                    }
                )
                rd_count += 1
                print(f'Created ResourceDefinition: {access.permission.permission} -> {luke_workspace_uuid}')
        
        print(f'\\n✅ Successfully created Luke\\'s complete RBAC setup:')
        print(f'   • Group: {luke_group.name}')
        print(f'   • Role: {luke_role.name}')
        print(f'   • Policy: {luke_policy.name}')
        print(f'   • ResourceDefinitions: {rd_count}')
        print(f'   • Workspace restriction: {luke_workspace_uuid}')
        
        # Verify the setup
        print('\\n🔍 Verification:')
        groups = Group.objects.filter(principals=luke_principal)
        policies = Policy.objects.filter(group__principals=luke_principal)
        print(f'Luke is in {groups.count()} groups: {[g.name for g in groups]}')
        print(f'Luke has {policies.count()} policies: {[p.name for p in policies]}')
        
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

echo "🔧 Creating Luke's RBAC setup..."
if oc exec "$RBAC_POD" -- bash -c "$CREATE_LUKE_GROUP_COMMAND"; then
    echo "✅ Luke's group and permissions created successfully"
else
    echo "❌ Failed to create Luke's group and permissions"
    exit 1
fi

echo ""
echo "🎉 Luke's Group Setup Completed!"
echo "================================"
echo ""
echo "✅ Created:"
echo "  • Group: luke-limited-group"
echo "  • Role: Luke Limited Viewer"
echo "  • Policy: luke-limited-policy"
echo "  • ResourceDefinitions with workspace restriction"
echo ""
echo "🧪 Test Luke's access:"
echo "   ./scripts/test_luke_permissions.sh"