#!/bin/bash

set -e

echo "🎯 Setting up Luke Demo"
echo "======================"
echo ""
echo "This script will:"
echo "  1. Create Luke user in RBAC with limited permissions"
echo "  2. Create Luke's workspace with 4 hosts"
echo "  3. Set up RBAC restrictions so Luke only sees his 4 hosts"
echo "  4. Test Luke's access"
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

# Create Luke user in RBAC
create_luke_user() {
    echo "👤 Creating Luke user in RBAC..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    # First check if Luke already exists
    local luke_exists
    luke_exists=$(oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOF'
from management.models import Principal
try:
    luke = Principal.objects.get(username='luke')
    print('EXISTS')
except Principal.DoesNotExist:
    print('NOT_EXISTS')
exit()
EOF" 2>/dev/null | grep -E '^(EXISTS|NOT_EXISTS)$' || echo "ERROR")

    if [[ "$luke_exists" == "EXISTS" ]]; then
        echo "✅ Luke user already exists"
        return 0
    elif [[ "$luke_exists" == "NOT_EXISTS" ]]; then
        echo "Creating new Luke user..."
    else
        echo "❌ ERROR: Could not check if Luke exists"
        exit 1
    fi
    
    # Create Luke user using the same approach as rbac_seed_users.sh
    echo "🔧 Creating Luke in RBAC system..."
    local creation_result
    creation_result=$(oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOF'
from management.management.commands.utils import process_batch
from management.models import Principal
import uuid

try:
    # Step 1: Create tenant and user via process_batch (like rbac_seed_users.sh)
    print('Creating tenant and user via process_batch...')
    process_batch([('12345', False, 'luke', '12350')])
    print('BATCH_COMPLETED')
    
    # Step 2: Manually create Principal entry (like rbac_seed_users.sh does)
    print('Creating Principal entry...')
    
    # Get the tenant ID for org_id 12345
    from api.models import Tenant
    tenant = Tenant.objects.get(org_id='12345')
    print(f'Found tenant: {tenant.id}')
    
    # Create Principal entry manually
    luke_uuid = str(uuid.uuid4())
    principal = Principal.objects.create(
        uuid=luke_uuid,
        username='luke',
        tenant_id=tenant.id,
        type='user',
        user_id='12350'
    )
    print(f'PRINCIPAL_CREATED: {principal.username} (ID: {principal.user_id})')
    
except Exception as e:
    print(f'ERROR: {e}')
    # Try to find Luke anyway
    try:
        luke = Principal.objects.get(username='luke')
        print(f'FOUND_EXISTING: Luke (ID: {luke.user_id})')
    except:
        print('CREATION_FAILED')

exit()
EOF" 2>/dev/null)

    echo "Creation result: $creation_result"
    
    if echo "$creation_result" | grep -q "PRINCIPAL_CREATED\|FOUND_EXISTING"; then
        echo "✅ Luke user setup completed successfully"
    else
        echo "❌ ERROR: Failed to create Luke user"
        echo "Full output: $creation_result"
        exit 1
    fi
}

# Create Luke's workspace with 4 hosts
create_luke_workspace() {
    echo "🏗️  Creating Luke's workspace with 4 hosts..."
    
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
    
    # Get first 4 hosts
    local luke_hosts
    luke_hosts=($(echo "$hosts_response" | jq -r '.results[].id' | head -4))
    
    if [[ ${#luke_hosts[@]} -lt 4 ]]; then
        echo "❌ ERROR: Not enough hosts available (found ${#luke_hosts[@]}, need 4)"
        exit 1
    fi
    
    echo "Selected 4 hosts for Luke: ${luke_hosts[*]:0:4}"
    
    # Create workspace with timestamp for uniqueness
    local timestamp
    timestamp=$(date +%s%N)  # Use nanoseconds for better uniqueness
    local workspace_name="luke-workspace-$timestamp"
    
    local luke_host_ids_json
    luke_host_ids_json=$(printf '%s\n' "${luke_hosts[@]}" | jq -R . | jq -s .)
    
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
            -d "{\"name\":\"$workspace_name\",\"host_ids\":$luke_host_ids_json}")
        
        if echo "$workspace_response" | jq -e '.id' >/dev/null 2>&1; then
            LUKE_WORKSPACE_UUID=$(echo "$workspace_response" | jq -r '.id')
            echo "✅ Luke's workspace created: $LUKE_WORKSPACE_UUID"
            echo "✅ 4 hosts assigned to Luke's workspace"
            return 0
        else
            retry_count=$((retry_count + 1))
            if [[ $retry_count -lt $max_retries ]]; then
                echo "⚠️  Workspace creation failed (attempt $retry_count/$max_retries), retrying in 5 seconds..."
                echo "   Response: $workspace_response"
                sleep 5
            else
                echo "❌ Failed to create Luke's workspace after $max_retries attempts: $workspace_response"
                exit 1
            fi
        fi
    done
}

# Setup RBAC permissions for Luke
setup_luke_rbac() {
    echo "🔐 Setting up RBAC permissions for Luke..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    # First, get Luke's workspace UUID from the API (like create_luke_group.sh does)
    echo "📋 Getting Luke's workspace UUID..."
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    local workspaces_response
    workspaces_response=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
    
    local LUKE_WORKSPACE_UUID
    LUKE_WORKSPACE_UUID=$(echo "$workspaces_response" | jq -r '.results[] | select(.name | contains("luke-workspace")) | .id' | head -1)
    
    if [[ -z "$LUKE_WORKSPACE_UUID" || "$LUKE_WORKSPACE_UUID" == "null" ]]; then
        echo "❌ ERROR: Could not find Luke's workspace"
        echo "Available workspaces:"
        echo "$workspaces_response" | jq -r '.results[] | "  - \(.name) (ID: \(.id))"'
        exit 1
    fi
    
    echo "Found Luke's workspace: $LUKE_WORKSPACE_UUID"
    
    # Create Luke's group, policy, and permissions - using exact same structure as create_luke_group.sh
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
        
        # Create ResourceDefinitions for each access object
        rd_count = 0
        access_objects = Access.objects.filter(role=luke_role)
        for access in access_objects:
            if access.permission.permission.startswith('inventory:'):
                # Clear existing ResourceDefinitions
                ResourceDefinition.objects.filter(access=access).delete()
                
                # Create new ResourceDefinition (using json.dumps like setup_luke_demo.sh)
                rd = ResourceDefinition.objects.create(
                    access=access,
                    tenant=luke_principal.tenant,
                    attributeFilter=json.dumps({
                        'key': 'group.id',
                        'operation': 'in',
                        'value': [luke_workspace_uuid]
                    })
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

    echo "🔧 Creating Luke's RBAC setup..."
    if oc exec "$rbac_pod" -- bash -c "$CREATE_LUKE_GROUP_COMMAND"; then
        echo "✅ Luke's group and permissions created successfully"
    else
        echo "❌ Failed to create Luke's group and permissions"
        exit 1
    fi

    echo "✅ RBAC permissions configured for Luke"
}

# Test Luke's access
test_luke_access() {
    echo "🧪 Testing Luke's access..."
    
    local luke_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"luke","email":"luke@redhat.com","first_name":"Luke","last_name":"Smith","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12350","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local luke_header
    luke_header=$(echo -n "$luke_json" | base64 -w 0)
    
    echo "Testing Luke's host access..."
    local response
    response=$(curl -s -H "x-rh-identity: $luke_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/hosts")
    
    if echo "$response" | jq -e '.results' >/dev/null 2>&1; then
        local host_count
        host_count=$(echo "$response" | jq '.results | length')
        echo "📊 Luke can see $host_count hosts"
        
        if [[ "$host_count" -eq 4 ]]; then
            echo "✅ SUCCESS: Luke sees exactly 4 hosts (as expected)"
        elif [[ "$host_count" -gt 4 ]]; then
            echo "⚠️  WARNING: Luke sees $host_count hosts (expected 4)"
        else
            echo "❌ ERROR: Luke sees only $host_count hosts (expected 4)"
        fi
    else
        echo "❌ ERROR: Failed to get hosts for Luke"
        echo "Response: $response"
        return 1
    fi
}

# Main execution
main() {
    check_prerequisites
    setup_port_forward
    create_luke_user
    create_luke_workspace
    setup_luke_rbac
    
    echo ""
    echo "⏳ Waiting for RBAC changes to propagate..."
    sleep 5
    
    test_luke_access
    
    echo ""
    echo "🎉 LUKE DEMO SETUP COMPLETED!"
    echo "============================"
    echo ""
    echo "✅ What was created:"
    echo "  • Luke user in RBAC with limited permissions"
    echo "  • Luke's workspace with 4 hosts assigned"
    echo "  • RBAC ResourceDefinitions restricting Luke to his workspace"
    echo ""
    echo "📋 Luke's Details:"
    echo "  • Username: luke"
    echo "  • User ID: 12350"
    echo "  • Workspace UUID: $LUKE_WORKSPACE_UUID"
    echo "  • Expected host count: 4"
    echo ""
    echo "🧪 To test Luke's access again:"
    echo "   ./test/e2e/test_luke_permissions.sh"
    echo ""
    echo "📚 Luke should now only see 4 hosts in his assigned workspace!"
}

main "$@" 