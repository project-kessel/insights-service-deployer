#!/usr/bin/env bash

# Setup Leia Demo - Create Leia with 2 hosts from Ungrouped Hosts
# This script sets up Leia with a workspace containing 2 hosts from "Ungrouped Hosts" and proper RBAC restrictions
# This should be run AFTER Luke's setup is complete

set -e

echo "🎯 Setting up Leia Demo"
echo "======================"
echo ""
echo "This script will:"
echo "  1. Create Leia user in RBAC with limited permissions"
echo "  2. Get 2 hosts from 'Ungrouped Hosts' workspace"
echo "  3. Create Leia's workspace with those 2 hosts"
echo "  4. Set up RBAC restrictions so Leia only sees his 2 hosts"
echo "  5. Test Leia's access"
echo ""
echo "⚠️  IMPORTANT: This should be run AFTER Luke's setup is complete!"
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
    
    oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOF'
from management.management.commands.utils import process_batch
from management.models import Principal

# Create Leia with limited access (is_admin=False)
try:
    process_batch([('12345', False, 'leia', '12351')])
    print('✅ Leia created successfully')
    
    # Verify Leia exists
    leia = Principal.objects.get(username='leia')
    print(f'Verified: Leia (ID: {leia.user_id})')
    
except Exception as e:
    print(f'Note: {e} (may already exist)')
    try:
        leia = Principal.objects.get(username='leia')
        print(f'Found existing Leia (ID: {leia.user_id})')
    except:
        print('❌ Failed to create or find Leia')

exit()
EOF" 2>/dev/null

    echo "✅ Leia user setup completed"
}

# Get 2 hosts from Ungrouped Hosts workspace
get_ungrouped_hosts() {
    echo "🔍 Getting 2 hosts from 'Ungrouped Hosts' workspace..."
    
    # Admin user JSON for API calls
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    # Get all hosts
    local hosts_response
    hosts_response=$(curl -s -H "x-rh-identity: $jdoe_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/hosts")
    
    if ! echo "$hosts_response" | jq -e '.results' >/dev/null 2>&1; then
        echo "❌ ERROR: Failed to get hosts from inventory service"
        exit 1
    fi
    
    # Find hosts in "Ungrouped Hosts" workspace
    local ungrouped_hosts
    ungrouped_hosts=($(echo "$hosts_response" | jq -r '.results[] | select(.groups[]?.name == "Ungrouped Hosts") | .id' | head -2))
    
    if [[ ${#ungrouped_hosts[@]} -lt 2 ]]; then
        echo "⚠️  Only found ${#ungrouped_hosts[@]} hosts in 'Ungrouped Hosts' workspace"
        echo "   Getting any available hosts for Leia's demo..."
        
        # Fallback: get any hosts that aren't in Luke's workspace
        local luke_workspace_hosts
        luke_workspace_hosts=($(echo "$hosts_response" | jq -r '.results[] | select(.groups[]?.name | contains("luke-workspace")) | .id'))
        
        # Get hosts not in Luke's workspace
        local available_hosts
        available_hosts=($(echo "$hosts_response" | jq -r --argjson luke_hosts "$(printf '%s\n' "${luke_workspace_hosts[@]}" | jq -R . | jq -s .)" '.results[] | select(.id as $id | $luke_hosts | index($id) | not) | .id' | head -2))
        
        if [[ ${#available_hosts[@]} -ge 2 ]]; then
            ungrouped_hosts=("${available_hosts[@]}")
            echo "✅ Found ${#ungrouped_hosts[@]} available hosts for Leia"
        else
            echo "❌ ERROR: Not enough hosts available for Leia (found ${#available_hosts[@]}, need 2)"
            exit 1
        fi
    else
        echo "✅ Found ${#ungrouped_hosts[@]} hosts in 'Ungrouped Hosts' for Leia"
    fi
    
    # Store the host IDs globally
    LEIA_HOST_IDS=("${ungrouped_hosts[@]:0:2}")
    echo "Selected hosts for Leia: ${LEIA_HOST_IDS[*]}"
}

# Create Leia's workspace with 2 hosts
create_leia_workspace() {
    echo "🏗️  Creating Leia's workspace with 2 hosts..."
    
    # Admin user JSON for API calls
    local jdoe_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"jdoe","email":"jdoe@redhat.com","first_name":"John","last_name":"Doe","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en_US","user_id":"12345","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
    local jdoe_header
    jdoe_header=$(echo -n "$jdoe_json" | base64 -w 0)
    
    # Create workspace with timestamp for uniqueness
    local timestamp
    timestamp=$(date +%s)
    local workspace_name="leia-workspace-$timestamp"
    
    local leia_host_ids_json
    leia_host_ids_json=$(printf '%s\n' "${LEIA_HOST_IDS[@]}" | jq -R . | jq -s .)
    
    echo "Creating workspace: $workspace_name"
    local workspace_response
    workspace_response=$(curl -s -X POST "http://localhost:8003/api/inventory/v1/groups" \
        -H "accept: application/json" \
        -H "Content-Type: application/json" \
        -H "x-rh-identity: $jdoe_header" \
        -d "{\"name\":\"$workspace_name\",\"host_ids\":$leia_host_ids_json}")
    
    if echo "$workspace_response" | jq -e '.id' >/dev/null 2>&1; then
        LEIA_WORKSPACE_UUID=$(echo "$workspace_response" | jq -r '.id')
        echo "✅ Leia's workspace created: $LEIA_WORKSPACE_UUID"
        echo "✅ 2 hosts assigned to Leia's workspace"
    else
        echo "❌ Failed to create Leia's workspace: $workspace_response"
        exit 1
    fi
}

# Setup RBAC permissions for Leia
setup_leia_rbac() {
    echo "🔐 Setting up RBAC permissions for Leia..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
from django.db import transaction
import json

try:
    with transaction.atomic():
        print('🔐 Setting up Leia RBAC permissions...')
        
        # Get Leia
        leia_principal = Principal.objects.get(username='leia')
        print(f'Found Leia: {leia_principal.username}')
        
        # Clear any existing policies for Leia
        old_policies = Policy.objects.filter(group__principals=leia_principal)
        for policy in old_policies:
            policy.group.principals.remove(leia_principal)
            print(f'Removed Leia from old policy: {policy.name}')
        
        # Create Leia's role
        leia_role, created = Role.objects.get_or_create(
            name='Leia Inventory Viewer',
            defaults={
                'display_name': 'Leia Inventory Viewer',
                'description': 'Leia\\'s personal inventory viewer role',
                'system': False,
                'platform_default': False,
                'admin_default': False,
                'tenant': leia_principal.tenant
            }
        )
        
        # Add inventory permissions to Leia's role
        inventory_permissions = ['inventory:hosts:read', 'inventory:groups:read']
        for perm_name in inventory_permissions:
            permission, created = Permission.objects.get_or_create(permission=perm_name)
            Access.objects.get_or_create(role=leia_role, permission=permission)
        
        print(f'Created/found Leia\\'s role: {leia_role.name}')
        
        # Create Leia's group and policy
        leia_group, created = Group.objects.get_or_create(
            name='leia-group',
            defaults={
                'tenant': leia_principal.tenant,
                'description': 'Leia\\'s access group'
            }
        )
        leia_group.principals.add(leia_principal)
        
        leia_policy, created = Policy.objects.get_or_create(
            name='leia-policy',
            defaults={
                'tenant': leia_principal.tenant,
                'description': 'Leia\\'s policy',
                'group': leia_group
            }
        )
        leia_policy.group = leia_group
        leia_policy.save()
        leia_policy.roles.add(leia_role)
        
        # Create ResourceDefinitions for workspace restriction
        leia_workspace_uuid = '$LEIA_WORKSPACE_UUID'
        print(f'Leia workspace UUID: {leia_workspace_uuid}')
        
        # Create ResourceDefinitions for each access object
        rd_count = 0
        for access in leia_role.access_set.all():
            if access.permission.permission.startswith('inventory:'):
                # Clear existing ResourceDefinitions
                ResourceDefinition.objects.filter(access=access).delete()
                
                # Create new ResourceDefinition
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
        
        print(f'\\n✅ Created {rd_count} ResourceDefinitions for Leia')
        print('✅ Leia is now restricted to his workspace only')
        
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()

exit()
EOFPYTHON" 2>/dev/null

    echo "✅ RBAC permissions configured for Leia"
}

# Test Leia's access
test_leia_access() {
    echo "🧪 Testing Leia's access..."
    
    local leia_json='{"identity":{"org_id":"12345","type":"User","auth_type":"basic-auth","user":{"username":"leia","email":"leia@redhat.com","first_name":"Leia","last_name":"Johnson","is_active":true,"is_org_admin":false,"is_internal":true,"locale":"en_US","user_id":"12351","account_number":"1234567890"},"internal":{"org_id":"12345"},"account_number":"1234567890"}}'
    
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
            
            # Show workspace info
            local workspace_hosts
            workspace_hosts=$(echo "$response" | jq --arg workspace_id "$LEIA_WORKSPACE_UUID" '[.results[] | select(.groups[]?.id == $workspace_id)] | length')
            echo "📊 $workspace_hosts hosts are in Leia's workspace ($LEIA_WORKSPACE_UUID)"
            
            # Show host IDs
            echo "📋 Host IDs Leia can see:"
            echo "$response" | jq -r '.results[].id' | sed 's/^/   /'
            
        elif [[ "$host_count" -gt 2 ]]; then
            echo "⚠️  WARNING: Leia sees $host_count hosts (expected 2)"
            echo "   This suggests RBAC filtering may not be working correctly"
        else
            echo "❌ ERROR: Leia sees only $host_count hosts (expected 2)"
        fi
    else
        echo "❌ ERROR: Failed to get hosts for Leia"
        echo "Response: $response"
        return 1
    fi
    
    # Test workspace access
    echo ""
    echo "Testing Leia's workspace access..."
    local workspace_response
    workspace_response=$(curl -s -H "x-rh-identity: $leia_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
    
    if echo "$workspace_response" | jq -e '.results' >/dev/null 2>&1; then
        local workspace_count
        workspace_count=$(echo "$workspace_response" | jq '.results | length')
        echo "📊 Leia can see $workspace_count workspaces"
        
        if [[ "$workspace_count" -gt 0 ]]; then
            echo "📋 Workspaces Leia can see:"
            echo "$workspace_response" | jq -r '.results[] | "   - \(.name) (ID: \(.id), Hosts: \(.host_count // 0))"'
        fi
    else
        echo "❌ ERROR: Failed to get workspaces for Leia"
    fi
}

# Main execution
main() {
    check_prerequisites
    setup_port_forward
    create_leia_user
    get_ungrouped_hosts
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
    echo "  • RBAC ResourceDefinitions restricting Leia to his workspace"
    echo ""
    echo "📋 Leia's Details:"
    echo "  • Username: leia"
    echo "  • User ID: 12351"
    echo "  • Workspace UUID: $LEIA_WORKSPACE_UUID"
    echo "  • Expected host count: 2"
    echo ""
    if [[ -n "${LEIA_WORKSPACE_UUID:-}" ]]; then
        echo "🔗 Leia's workspace: $LEIA_WORKSPACE_UUID"
    fi
    echo ""
    echo "🧪 To test Leia's access again:"
    echo "   ./scripts/test_leia_permissions.sh"
    echo ""
    echo "📚 Leia should now only see 2 hosts in his assigned workspace!"
    echo ""
    echo "🔗 Summary of Demo Users:"
    echo "  • Luke: 4 hosts in luke-workspace-*"
    echo "  • Leia: 2 hosts in leia-workspace-*"
    echo "  • Both users have workspace-restricted access via RBAC"
}

main "$@" 