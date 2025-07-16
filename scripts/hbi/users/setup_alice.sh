#!/usr/bin/env bash

# Alice Demo Setup Script
# This script creates Alice with limited RBAC permissions and a workspace

set -e

echo "🎯 Setting up Alice Demo"
echo "======================="
echo ""
echo "This script will:"
echo "  1. Create Alice user in RBAC with limited permissions"
echo "  2. Create Alice's workspace with 4 hosts"
echo "  3. Set up RBAC restrictions so Alice only sees her 4 hosts"
echo "  4. Test Alice's access"
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

# Get available hosts and select 4 for Alice
select_hosts_for_alice() {
    echo "🏗️  Selecting 4 hosts for Alice's workspace..."
    
    # Admin user JSON for API calls
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    # Get all hosts
    echo "📡 Getting available hosts..."
    local hosts_response
    hosts_response=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/hosts")
    
    # Check if we got a valid response
    if [[ -z "$hosts_response" ]]; then
        echo "❌ ERROR: Empty response from hosts API"
        exit 1
    fi
    
    # Check if response has results
    local total_hosts
    total_hosts=$(echo "$hosts_response" | jq -r '.total // 0')
    
    if [[ "$total_hosts" -eq 0 ]]; then
        echo "❌ ERROR: No hosts available in inventory"
        echo "Response: $hosts_response"
        exit 1
    fi
    
    echo "📋 Found $total_hosts total hosts available"
    
    # Check if we have enough hosts
    if [[ "$total_hosts" -lt 4 ]]; then
        echo "❌ ERROR: Not enough hosts available (found $total_hosts, need 4)"
        exit 1
    fi
    
    # Select first 4 hosts safely
    ALICE_HOST_IDS=($(echo "$hosts_response" | jq -r '.results[0:4][]?.id // empty'))
    
    if [[ ${#ALICE_HOST_IDS[@]} -lt 4 ]]; then
        echo "❌ ERROR: Could not select 4 hosts (found ${#ALICE_HOST_IDS[@]})"
        echo "Available hosts:"
        echo "$hosts_response" | jq -r '.results[]?.id // empty' | head -10
        exit 1
    fi
    
    echo "Selected 4 hosts for Alice: ${ALICE_HOST_IDS[*]}"
    
    # Verify each host exists and get their current group status
    echo "🔍 Verifying selected hosts..."
    for host_id in "${ALICE_HOST_IDS[@]}"; do
        local host_detail
        host_detail=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/hosts/$host_id")
        
        if [[ -z "$host_detail" ]] || echo "$host_detail" | jq -e '.detail' >/dev/null 2>&1; then
            echo "❌ ERROR: Host $host_id not accessible or doesn't exist"
            echo "Response: $host_detail"
            exit 1
        fi
        
        local current_groups
        current_groups=$(echo "$host_detail" | jq -r '.groups[]?.name // "Ungrouped"' | tr '\n' ', ' | sed 's/,$//')
        echo "   Host $host_id: Currently in [$current_groups]"
    done
    
    echo "✅ All selected hosts verified and accessible"
}

# Create Alice's workspace
create_alice_workspace() {
    echo "🏗️  Creating Alice's workspace with 4 hosts..."
    
    # Admin user JSON for API calls
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    # Create workspace with timestamp for uniqueness
    local timestamp
    timestamp=$(date +%s)
    local workspace_name="alice-workspace-$timestamp"
    
    local alice_host_ids_json
    alice_host_ids_json=$(printf '%s\n' "${ALICE_HOST_IDS[@]}" | jq -R . | jq -s .)
    
    echo "Creating workspace: $workspace_name"
    
    # Add retry logic for workspace creation
    local max_retries=3
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        workspace_response=$(curl -s -X POST "http://localhost:8003/api/inventory/v1/groups" \
            -H "accept: application/json" \
            -H "Content-Type: application/json" \
            -H "x-rh-identity: $jdoe_header" \
            -d "{\"name\":\"$workspace_name\",\"host_ids\":$alice_host_ids_json}")
        
        if echo "$workspace_response" | jq -e '.id' >/dev/null 2>&1; then
            ALICE_WORKSPACE_UUID=$(echo "$workspace_response" | jq -r '.id')
            echo "✅ Alice's workspace created: $ALICE_WORKSPACE_UUID"
            echo "✅ 4 hosts assigned to Alice's workspace"
            return 0
        else
            retry_count=$((retry_count + 1))
            if [[ $retry_count -lt $max_retries ]]; then
                echo "⚠️  Workspace creation failed (attempt $retry_count/$max_retries), retrying in 5 seconds..."
                echo "   Response: $workspace_response"
                sleep 5
            else
                echo "❌ Failed to create Alice's workspace after $max_retries attempts: $workspace_response"
                exit 1
            fi
        fi
    done
}

# Setup RBAC permissions for Alice
setup_alice_rbac() {
    echo "🔐 Setting up RBAC permissions for Alice..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    # First, get Alice's workspace UUID from the API
    echo "📋 Getting Alice's workspace UUID..."
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    local workspaces_response
    workspaces_response=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
    
    local ALICE_WORKSPACE_UUID_CHECK
    ALICE_WORKSPACE_UUID_CHECK=$(echo "$workspaces_response" | jq -r '.results[] | select(.name | contains("alice-workspace")) | .id' | head -1)
    
    if [[ -z "$ALICE_WORKSPACE_UUID_CHECK" || "$ALICE_WORKSPACE_UUID_CHECK" == "null" ]]; then
        echo "❌ ERROR: Could not find Alice's workspace"
        echo "Available workspaces:"
        echo "$workspaces_response" | jq -r '.results[] | "  - \(.name) (ID: \(.id))"'
        exit 1
    fi
    
    echo "Found Alice's workspace: $ALICE_WORKSPACE_UUID_CHECK"
    
    # Use the confirmed workspace UUID
    ALICE_WORKSPACE_UUID="$ALICE_WORKSPACE_UUID_CHECK"
    
    # Create Alice's group, policy, and permissions
    CREATE_ALICE_GROUP_COMMAND="./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
from django.db import transaction
import json

try:
    with transaction.atomic():
        print('🔧 Creating Alice\\'s Group and Permissions...')
        
        # Get Alice
        alice_principal = Principal.objects.get(username='alice')
        print(f'Found Alice: {alice_principal.username} (ID: {alice_principal.user_id})')
        print(f'Alice tenant: {alice_principal.tenant}')
        
        # Remove Alice from any existing groups/policies
        existing_policies = Policy.objects.filter(group__principals=alice_principal)
        for policy in existing_policies:
            policy.group.principals.remove(alice_principal)
            print(f'Removed Alice from existing policy: {policy.name}')
        
        # Create Alice's group
        alice_group, created = Group.objects.get_or_create(
            name='alice-limited-group',
            defaults={
                'tenant': alice_principal.tenant,
                'description': 'Alice\\'s limited access group'
            }
        )
        
        if created:
            print(f'Created new group: {alice_group.name}')
        else:
            print(f'Found existing group: {alice_group.name}')
        
        # Add Alice to her group
        alice_group.principals.add(alice_principal)
        print(f'Added Alice to group: {alice_group.name}')
        
        # Create Alice's role
        alice_role, created = Role.objects.get_or_create(
            name='Alice Limited Viewer',
            defaults={
                'display_name': 'Alice Limited Viewer',
                'description': 'Alice\\'s limited viewer role',
                'system': False,
                'platform_default': False,
                'admin_default': False,
                'tenant': alice_principal.tenant
            }
        )
        
        if created:
            print(f'Created new role: {alice_role.name}')
        else:
            print(f'Found existing role: {alice_role.name}')
        
        # Add permissions to Alice's role (with proper tenant_id)
        inventory_permissions = ['inventory:hosts:read', 'inventory:groups:read']
        for perm_name in inventory_permissions:
            permission, created = Permission.objects.get_or_create(permission=perm_name)
            # Create Access object with explicit tenant_id
            access, created = Access.objects.get_or_create(
                role=alice_role,
                permission=permission,
                defaults={'tenant': alice_principal.tenant}
            )
            if created:
                print(f'Added permission: {perm_name} (with tenant: {alice_principal.tenant})')
            else:
                # Update existing access to ensure it has tenant_id
                if not access.tenant:
                    access.tenant = alice_principal.tenant
                    access.save()
                    print(f'Updated permission tenant: {perm_name}')
        
        # Create Alice's policy
        alice_policy, created = Policy.objects.get_or_create(
            name='alice-limited-policy',
            defaults={
                'tenant': alice_principal.tenant,
                'description': 'Alice\\'s limited policy',
                'group': alice_group
            }
        )
        
        if created:
            print(f'Created new policy: {alice_policy.name}')
        else:
            print(f'Found existing policy: {alice_policy.name}')
            alice_policy.group = alice_group
            alice_policy.save()
        
        # Assign role to policy
        alice_policy.roles.add(alice_role)
        print(f'Assigned role {alice_role.name} to policy {alice_policy.name}')
        
        # Create ResourceDefinitions for workspace restriction
        alice_workspace_uuid = '$ALICE_WORKSPACE_UUID'
        print(f'Alice workspace UUID: {alice_workspace_uuid}')
        
        # Create ResourceDefinitions for each access object
        rd_count = 0
        access_objects = Access.objects.filter(role=alice_role)
        for access in access_objects:
            if access.permission.permission.startswith('inventory:'):
                # Clear existing ResourceDefinitions
                ResourceDefinition.objects.filter(access=access).delete()
                
                # Create new ResourceDefinition (store as dict, not JSON string)
                rd = ResourceDefinition.objects.create(
                    access=access,
                    tenant=alice_principal.tenant,
                    attributeFilter={
                        'key': 'group.id',
                        'operation': 'in',
                        'value': [alice_workspace_uuid]
                    }
                )
                rd_count += 1
                print(f'Created ResourceDefinition: {access.permission.permission} -> {alice_workspace_uuid}')
        
        print(f'\\n✅ Successfully created Alice\\'s complete RBAC setup:')
        print(f'   • Group: {alice_group.name}')
        print(f'   • Role: {alice_role.name}')
        print(f'   • Policy: {alice_policy.name}')
        print(f'   • ResourceDefinitions: {rd_count}')
        print(f'   • Workspace restriction: {alice_workspace_uuid}')
        
        # Verify the setup
        print('\\n🔍 Verification:')
        groups = Group.objects.filter(principals=alice_principal)
        policies = Policy.objects.filter(group__principals=alice_principal)
        print(f'Alice is in {groups.count()} groups: {[g.name for g in groups]}')
        print(f'Alice has {policies.count()} policies: {[p.name for p in policies]}')
        
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

    echo "🔧 Creating Alice's RBAC setup..."
    if oc exec "$rbac_pod" -- bash -c "$CREATE_ALICE_GROUP_COMMAND"; then
        echo "✅ Alice's group and permissions created successfully"
    else
        echo "❌ Failed to create Alice's group and permissions"
        exit 1
    fi

    echo "✅ RBAC permissions configured for Alice"
}

# Print summary
print_summary() {
    echo ""
    echo "🎉 ALICE DEMO SETUP COMPLETED!"
    echo "=============================="
    echo ""
    echo "✅ What was created:"
    echo "  • Alice user in RBAC with limited permissions"
    echo "  • Alice's workspace with 4 hosts assigned"
    echo "  • RBAC ResourceDefinitions restricting Alice to her workspace"
    echo ""
    echo "📋 Alice's Details:"
    echo "  • Username: alice"
    echo "  • User ID: 12347"
    echo "  • Workspace UUID: $ALICE_WORKSPACE_UUID"
    echo "  • Expected host count: 4"
    echo ""
    echo "🧪 To test Alice's access again:"
    echo "   ./test/e2e/test_alice_permissions.sh"
    echo ""
    echo "📚 Alice should now only see 4 hosts in her assigned workspace!"
}

# Main execution
main() {
    check_prerequisites
    setup_port_forwarding
    select_hosts_for_alice
    create_alice_workspace
    setup_alice_rbac
    print_summary
}

# Run main function
main "$@" 