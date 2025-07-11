#!/bin/bash

set -e

echo "🎯 Setting up Leia Demo"
echo "======================"
echo ""
echo "This script will:"
echo "  1. Create Leia user in RBAC with limited permissions"
echo "  2. Create Leia's workspace with 2 hosts"
echo "  3. Set up RBAC restrictions so Leia only sees her 2 hosts"
echo "  4. Test Leia's access"
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
    
    if ! oc get pods -l pod=host-inventory-service-reads --no-headers 2>/dev/null | grep -q Running; then
        echo "❌ ERROR: Host inventory service not running"
        exit 1
    fi
    
    echo "✅ Prerequisites check passed"
    echo "   Namespace: $NAMESPACE"
    echo ""
}

# Setup port forwarding
setup_port_forward() {
    echo "🔧 Setting up port forwarding..."
    
    # Kill any existing port forwards
    pkill -f "oc port-forward.*800[23]" 2>/dev/null || true
    sleep 2
    
    local reads_pod
    reads_pod=$(oc get pods -l pod=host-inventory-service-reads --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
    
    local writes_pod
    writes_pod=$(oc get pods -l pod=host-inventory-service-writes --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
    
    echo "Starting port forwards..."
    oc port-forward "$reads_pod" 8002:8000 >/dev/null 2>&1 &
    oc port-forward "$writes_pod" 8003:8000 >/dev/null 2>&1 &
    
    sleep 3
    echo "✅ Port forwarding established"
}

cleanup_port_forward() {
    pkill -f "oc port-forward.*800[23]" 2>/dev/null || true
}
trap cleanup_port_forward EXIT

# Create Leia user in RBAC
create_leia_user() {
    echo "👤 Creating Leia user in RBAC..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    # First check if Leia already exists
    local leia_exists
    leia_exists=$(oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOF'
from management.models import Principal
try:
    leia = Principal.objects.get(username='leia')
    print('EXISTS')
except Principal.DoesNotExist:
    print('NOT_EXISTS')
exit()
EOF" 2>/dev/null | grep -E '^(EXISTS|NOT_EXISTS)$' || echo "ERROR")

    if [[ "$leia_exists" == "EXISTS" ]]; then
        echo "✅ Leia user already exists"
        return 0
    elif [[ "$leia_exists" == "NOT_EXISTS" ]]; then
        echo "Creating new Leia user..."
    else
        echo "❌ ERROR: Could not check if Leia exists"
        exit 1
    fi
    
    # Create Leia user using the same approach as rbac_seed_users.sh
    echo "🔧 Creating Leia in RBAC system..."
    local creation_result
    creation_result=$(oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOF'
from management.management.commands.utils import process_batch
from management.models import Principal
import uuid

try:
    # Step 1: Create tenant and user via process_batch (like rbac_seed_users.sh)
    print('Creating tenant and user via process_batch...')
    process_batch([('12345', False, 'leia', '12351')])
    print('BATCH_COMPLETED')
    
    # Step 2: Manually create Principal entry (like rbac_seed_users.sh does)
    print('Creating Principal entry...')
    
    # Get the tenant ID for org_id 12345
    from api.models import Tenant
    tenant = Tenant.objects.get(org_id='12345')
    print(f'Found tenant: {tenant.id}')
    
    # Create Principal entry manually
    leia_uuid = str(uuid.uuid4())
    principal = Principal.objects.create(
        uuid=leia_uuid,
        username='leia',
        tenant_id=tenant.id,
        type='user',
        user_id='12351'
    )
    print(f'PRINCIPAL_CREATED: {principal.username} (ID: {principal.user_id})')
    
except Exception as e:
    print(f'ERROR: {e}')
    # Try to find Leia anyway
    try:
        leia = Principal.objects.get(username='leia')
        print(f'FOUND_EXISTING: Leia (ID: {leia.user_id})')
    except:
        print('CREATION_FAILED')

exit()
EOF" 2>/dev/null)

    echo "Creation result: $creation_result"
    
    if echo "$creation_result" | grep -q "PRINCIPAL_CREATED\|FOUND_EXISTING"; then
        echo "✅ Leia user setup completed successfully"
    else
        echo "❌ ERROR: Failed to create Leia user"
        echo "Full output: $creation_result"
        exit 1
    fi
}

# Create Leia's workspace with 2 hosts
create_leia_workspace() {
    echo "🏗️  Creating Leia's workspace with 2 hosts..."
    
    # Admin user JSON for API calls
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    # Get available hosts
    local hosts_response
    hosts_response=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/hosts")
    
    if ! echo "$hosts_response" | jq -e '.results' >/dev/null 2>&1; then
        echo "❌ ERROR: Failed to get hosts from inventory service"
        exit 1
    fi
    
    # Get hosts 5-6 (skip first 4 that Luke might have)
    local leia_hosts
    leia_hosts=($(echo "$hosts_response" | jq -r '.results[].id' | tail -n +5 | head -2))
    
    if [[ ${#leia_hosts[@]} -lt 2 ]]; then
        echo "❌ ERROR: Not enough hosts available (found ${#leia_hosts[@]}, need 2)"
        exit 1
    fi
    
    echo "Selected 2 hosts for Leia: ${leia_hosts[*]:0:2}"
    
    # Create workspace with timestamp for uniqueness
    local timestamp
    timestamp=$(date +%s)
    local workspace_name="leia-workspace-$timestamp"
    
    local leia_host_ids_json
    leia_host_ids_json=$(printf '%s\n' "${leia_hosts[@]}" | jq -R . | jq -s .)
    
    echo "Creating workspace: $workspace_name"
    
    # Wait a moment for RBAC to be ready
    echo "⏳ Waiting for RBAC to be ready..."
    sleep 3
    
    # Retry workspace creation up to 3 times
    local max_retries=3
    local retry_count=0
    local workspace_response=""
    
    while [[ $retry_count -lt $max_retries ]]; do
        workspace_response=$(curl -s -X POST "http://localhost:8003/api/inventory/v1/groups" \
            -H "accept: application/json" \
            -H "Content-Type: application/json" \
            -H "x-rh-identity: $jdoe_header" \
            -d "{\"name\":\"$workspace_name\",\"host_ids\":$leia_host_ids_json}")
        
        if echo "$workspace_response" | jq -e '.id' >/dev/null 2>&1; then
            LEIA_WORKSPACE_UUID=$(echo "$workspace_response" | jq -r '.id')
            echo "✅ Leia's workspace created: $LEIA_WORKSPACE_UUID"
            echo "✅ 2 hosts assigned to Leia's workspace"
            return 0
        else
            retry_count=$((retry_count + 1))
            if [[ $retry_count -lt $max_retries ]]; then
                echo "⚠️  Workspace creation failed (attempt $retry_count/$max_retries), retrying in 5 seconds..."
                echo "   Response: $workspace_response"
                sleep 5
            else
                echo "❌ Failed to create Leia's workspace after $max_retries attempts: $workspace_response"
                exit 1
            fi
        fi
    done
}

# Setup RBAC permissions for Leia
setup_leia_rbac() {
    echo "🔐 Setting up RBAC permissions for Leia..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    # First, get Leia's workspace UUID from the API
    echo "📋 Getting Leia's workspace UUID..."
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    local workspaces_response
    workspaces_response=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
    
    local LEIA_WORKSPACE_UUID
    LEIA_WORKSPACE_UUID=$(echo "$workspaces_response" | jq -r '.results[] | select(.name | contains("leia-workspace")) | .id' | head -1)
    
    if [[ -z "$LEIA_WORKSPACE_UUID" || "$LEIA_WORKSPACE_UUID" == "null" ]]; then
        echo "❌ ERROR: Could not find Leia's workspace"
        echo "Available workspaces:"
        echo "$workspaces_response" | jq -r '.results[] | "  - \(.name) (ID: \(.id))"'
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
        
        # Add Leia to her group
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
        
        # Create ResourceDefinitions for each access object
        rd_count = 0
        access_objects = Access.objects.filter(role=leia_role)
        for access in access_objects:
            if access.permission.permission.startswith('inventory:'):
                # Clear existing ResourceDefinitions
                ResourceDefinition.objects.filter(access=access).delete()
                
                # Create new ResourceDefinition (store as dict, not JSON string)
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
                            try:
                                filter_data = json.loads(rd.attributeFilter) if isinstance(rd.attributeFilter, str) else rd.attributeFilter
                                filter_value = filter_data.get(\"value\", [])
                                print(f\"    ResourceDefinition: {filter_value}\")
                            except:
                                print(f\"    ResourceDefinition: {rd.attributeFilter}\")
                        else:
                            print(f\"    ResourceDefinition: No filter\")
        
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()

exit()
EOFPYTHON"

    echo "🔧 Creating Leia's RBAC setup..."
    if oc exec "$rbac_pod" -- bash -c "$CREATE_LEIA_GROUP_COMMAND"; then
        echo "✅ Leia's group and permissions created successfully"
    else
        echo "❌ Failed to create Leia's group and permissions"
        exit 1
    fi

    echo "✅ RBAC permissions configured for Leia"
}

# Test Leia's access
test_leia_access() {
    echo "🧪 Testing Leia's access..."
    
    local leia_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"leia","email":"leia@redhat.com","first_name":"Leia","last_name":"Organa","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12351","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local leia_header
    leia_header=$(echo -n "$leia_json" | base64 -w 0)
    
    echo "Testing Leia's host access..."
    local response
    response=$(curl -s -H "x-rh-identity: $leia_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/hosts")
    
    if echo "$response" | jq -e '.results' >/dev/null 2>&1; then
        local host_count
        host_count=$(echo "$response" | jq '.results | length')
        echo "📊 Leia can see $host_count hosts"
        
        if [[ "$host_count" -eq 2 ]]; then
            echo "✅ SUCCESS: Leia sees exactly 2 hosts (as expected)"
        elif [[ "$host_count" -gt 2 ]]; then
            echo "⚠️  WARNING: Leia sees $host_count hosts (expected 2)"
        else
            echo "❌ ERROR: Leia sees only $host_count hosts (expected 2)"
        fi
    else
        echo "❌ ERROR: Failed to get hosts for Leia"
        echo "Response: $response"
        return 1
    fi
}

# Main execution
main() {
    check_prerequisites
    setup_port_forward
    create_leia_user
    create_leia_workspace
    setup_leia_rbac
    
    echo ""
    echo "⏳ Waiting for RBAC changes to propagate..."
    sleep 5
    
    test_leia_access
    
    echo ""
    echo "🎉 LEIA DEMO SETUP COMPLETED!"
    echo "============================"
    echo ""
    echo "✅ What was created:"
    echo "  • Leia user in RBAC with limited permissions"
    echo "  • Leia's workspace with 2 hosts assigned"
    echo "  • RBAC ResourceDefinitions restricting Leia to her workspace"
    echo ""
    echo "📋 Leia's Details:"
    echo "  • Username: leia"
    echo "  • User ID: 12351"
    echo "  • Workspace UUID: $LEIA_WORKSPACE_UUID"
    echo "  • Expected host count: 2"
    echo ""
    echo "🧪 To test Leia's access again:"
    echo "   ./test/e2e/test_leia_permissions.sh"
    echo ""
    echo "📚 Leia should now only see 2 hosts in her assigned workspace!"
}

main "$@" 