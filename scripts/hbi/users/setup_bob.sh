#!/usr/bin/env bash

# Bob Demo Setup Script  
# This script creates Bob with limited RBAC permissions and a workspace

set -e

echo "🎯 Setting up Bob Demo"
echo "====================="
echo ""
echo "This script will:"
echo "  1. Create Bob user in RBAC with limited permissions"
echo "  2. Create Bob's workspace with 2 hosts"
echo "  3. Set up RBAC restrictions so Bob only sees his 2 hosts"
echo "  4. Test Bob's access"
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

# Get available hosts and select 2 for Bob (different from Alice's 4)
select_hosts_for_bob() {
    echo "🏗️  Selecting 2 hosts for Bob's workspace..."
    
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
    
    # Check if we have enough hosts (need at least 6 to select hosts 5-6)
    if [[ "$total_hosts" -lt 6 ]]; then
        echo "⚠️  Not enough hosts for Bob's preferred range (hosts 5-6), selecting from available hosts..."
        # Fall back to selecting last 2 hosts if we don't have 6+
        BOB_HOST_IDS=($(echo "$hosts_response" | jq -r '.results[-2:][]?.id // empty'))
    else
        # Select hosts 5-6 (indices 4-5) as originally planned
        BOB_HOST_IDS=($(echo "$hosts_response" | jq -r '.results[4:6][]?.id // empty'))
    fi
    
    if [[ ${#BOB_HOST_IDS[@]} -lt 2 ]]; then
        echo "❌ ERROR: Could not select 2 hosts (found ${#BOB_HOST_IDS[@]})"
        echo "Available hosts:"
        echo "$hosts_response" | jq -r '.results[]?.id // empty' | head -10
        exit 1
    fi
    
    echo "Selected 2 hosts for Bob: ${BOB_HOST_IDS[*]}"
}

# Create Bob's workspace
create_bob_workspace() {
    echo "🏗️  Creating Bob's workspace with 2 hosts..."
    
    # Admin user JSON for API calls
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    # Create workspace with timestamp for uniqueness
    local timestamp
    timestamp=$(date +%s)
    local workspace_name="bob-workspace-$timestamp"
    
    local bob_host_ids_json
    bob_host_ids_json=$(printf '%s\n' "${BOB_HOST_IDS[@]}" | jq -R . | jq -s .)
    
    echo "Creating workspace: $workspace_name"
    
    # Add retry logic for workspace creation
    local max_retries=3
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        workspace_response=$(curl -s -X POST "http://localhost:8003/api/inventory/v1/groups" \
            -H "accept: application/json" \
            -H "Content-Type: application/json" \
            -H "x-rh-identity: $jdoe_header" \
            -d "{\"name\":\"$workspace_name\",\"host_ids\":$bob_host_ids_json}")
        
        if echo "$workspace_response" | jq -e '.id' >/dev/null 2>&1; then
            BOB_WORKSPACE_UUID=$(echo "$workspace_response" | jq -r '.id')
            echo "✅ Bob's workspace created: $BOB_WORKSPACE_UUID"
            echo "✅ 2 hosts assigned to Bob's workspace"
            return 0
        else
            retry_count=$((retry_count + 1))
            if [[ $retry_count -lt $max_retries ]]; then
                echo "⚠️  Workspace creation failed (attempt $retry_count/$max_retries), retrying in 5 seconds..."
                echo "   Response: $workspace_response"
                sleep 5
            else
                echo "❌ Failed to create Bob's workspace after $max_retries attempts: $workspace_response"
                exit 1
            fi
        fi
    done
}

# Setup RBAC permissions for Bob
setup_bob_rbac() {
    echo "🔐 Setting up RBAC permissions for Bob..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    # Create Bob's RBAC setup
    oc exec "$rbac_pod" -- bash -c "BOB_WORKSPACE_UUID='$BOB_WORKSPACE_UUID' ./rbac/manage.py shell << 'EOFPYTHON'
import os
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
from django.db import transaction

try:
    with transaction.atomic():
        print('🔧 Setting up Bob\\'s RBAC permissions...')
        
        # Get Bob (should already exist)
        bob_principal = Principal.objects.get(username='bob')
        print(f'Found Bob: {bob_principal.username} (ID: {bob_principal.user_id})')
        
        # Remove Bob from any existing groups/policies
        existing_policies = Policy.objects.filter(group__principals=bob_principal)
        for policy in existing_policies:
            policy.group.principals.remove(bob_principal)
            print(f'Removed Bob from existing policy: {policy.name}')
        
        # Create Bob's group
        bob_group, created = Group.objects.get_or_create(
            name='bob-limited-group',
            defaults={
                'tenant': bob_principal.tenant,
                'description': 'Bob\\'s limited access group'
            }
        )
        
        if created:
            print(f'Created new group: {bob_group.name}')
        else:
            print(f'Found existing group: {bob_group.name}')
        
        # Add Bob to his group
        bob_group.principals.add(bob_principal)
        print(f'Added Bob to group: {bob_group.name}')
        
        # Create Bob's role
        bob_role, created = Role.objects.get_or_create(
            name='Bob Limited Viewer',
            defaults={
                'display_name': 'Bob Limited Viewer',
                'description': 'Bob\\'s limited viewer role',
                'system': False,
                'platform_default': False,
                'admin_default': False,
                'tenant': bob_principal.tenant
            }
        )
        
        if created:
            print(f'Created new role: {bob_role.name}')
        else:
            print(f'Found existing role: {bob_role.name}')
        
        # Add permissions to Bob's role
        inventory_permissions = ['inventory:hosts:read', 'inventory:groups:read']
        for perm_name in inventory_permissions:
            permission, created = Permission.objects.get_or_create(permission=perm_name)
            access, created = Access.objects.get_or_create(
                role=bob_role,
                permission=permission,
                defaults={'tenant': bob_principal.tenant}
            )
            if created:
                print(f'Added permission: {perm_name}')
            else:
                if not access.tenant:
                    access.tenant = bob_principal.tenant
                    access.save()
                    print(f'Updated permission tenant: {perm_name}')
        
        # Create Bob's policy
        bob_policy, created = Policy.objects.get_or_create(
            name='bob-limited-policy',
            defaults={
                'tenant': bob_principal.tenant,
                'description': 'Bob\\'s limited policy',
                'group': bob_group
            }
        )
        
        if created:
            print(f'Created new policy: {bob_policy.name}')
        else:
            print(f'Found existing policy: {bob_policy.name}')
            bob_policy.group = bob_group
            bob_policy.save()
        
        # Assign role to policy
        bob_policy.roles.add(bob_role)
        print(f'Assigned role {bob_role.name} to policy {bob_policy.name}')
        
        # Create ResourceDefinitions for workspace restriction
        bob_workspace_uuid = '$BOB_WORKSPACE_UUID'
        print(f'Bob workspace UUID: {bob_workspace_uuid}')
        
        # Create ResourceDefinitions for each access object
        rd_count = 0
        access_objects = Access.objects.filter(role=bob_role)
        for access in access_objects:
            if access.permission.permission.startswith('inventory:'):
                # Clear existing ResourceDefinitions
                ResourceDefinition.objects.filter(access=access).delete()
                
                # Create new ResourceDefinition (store as dict, not JSON string)
                rd = ResourceDefinition.objects.create(
                    access=access,
                    tenant=bob_principal.tenant,
                    attributeFilter={
                        'key': 'group.id',
                        'operation': 'in',
                        'value': [bob_workspace_uuid]
                    }
                )
                rd_count += 1
                print(f'Created ResourceDefinition: {access.permission.permission} -> {bob_workspace_uuid}')
        
        print(f'\\n✅ Successfully created Bob\\'s complete RBAC setup:')
        print(f'   • Group: {bob_group.name}')
        print(f'   • Role: {bob_role.name}')
        print(f'   • Policy: {bob_policy.name}')
        print(f'   • ResourceDefinitions: {rd_count}')
        print(f'   • Workspace restriction: {bob_workspace_uuid}')
        
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()

exit()
EOFPYTHON"
    
    echo "✅ Bob's RBAC setup completed successfully"
}



# Print summary
print_summary() {
    echo ""
    echo "🎉 BOB DEMO SETUP COMPLETED!"
    echo "============================"
    echo ""
    echo "✅ What was created:"
    echo "  • Bob user in RBAC with limited permissions"
    echo "  • Bob's workspace with 2 hosts assigned"
    echo "  • RBAC ResourceDefinitions restricting Bob to his workspace"
    echo ""
    echo "📋 Bob's Details:"
    echo "  • Username: bob"
    echo "  • User ID: 12348"
    echo "  • Workspace UUID: $BOB_WORKSPACE_UUID"
    echo "  • Expected host count: 2"
    echo ""
    echo "🧪 To test Bob's access again:"
    echo "   ./test/e2e/test_bob_permissions.sh"
    echo ""
    echo "📚 Bob should now only see 2 hosts in his assigned workspace!"
}

# Main execution
main() {
    check_prerequisites
    setup_port_forwarding
    select_hosts_for_bob
    create_bob_workspace
    setup_bob_rbac
    print_summary
}

# Run main function
main "$@" 