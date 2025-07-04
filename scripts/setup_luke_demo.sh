#!/usr/bin/env bash

# Setup Luke Demo - Consolidated Script
# This script sets up Luke with a workspace containing 4 hosts and proper RBAC restrictions

set -e

echo "🎯 Setting up Luke Demo"
echo "======================"
echo ""
echo "This script will:"
echo "  1. Ensure we have enough hosts (add more if needed)"
echo "  2. Create Luke user in RBAC with limited permissions"
echo "  3. Create Luke's workspace with 4 hosts"
echo "  4. Set up RBAC restrictions so Luke only sees his 4 hosts"
echo "  5. Test Luke's access"
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

# Ensure we have enough hosts
ensure_hosts() {
    echo "📊 Checking host count..."
    
    local host_count
    local db_pod
    db_pod=$(oc get pods -l app=host-inventory,service=db,sub=local_db --no-headers -o custom-columns=":metadata.name" --field-selector=status.phase==Running | head -1)
    
    if [[ -z "$db_pod" ]]; then
        echo "❌ ERROR: Could not find host inventory database pod"
        exit 1
    fi
    
    host_count=$(oc exec "$db_pod" -- psql -d host-inventory -t -c "select count(*) from hbi.hosts;" 2>/dev/null | tr -d '[:space:]' || echo "0")
    
    echo "Current host count: $host_count"
    
    if [[ "$host_count" -lt 10 ]]; then
        echo "⚠️  Need at least 10 hosts for reliable demo (current: $host_count)"
        echo "🔄 Adding more hosts..."
        
        # Use the deploy.sh script to add hosts
        if [[ -f "../deploy.sh" ]]; then
            ../deploy.sh add_hosts_to_hbi 12345 15
        elif [[ -f "./deploy.sh" ]]; then
            ./deploy.sh add_hosts_to_hbi 12345 15
        else
            echo "❌ ERROR: Could not find deploy.sh script"
            exit 1
        fi
        
        echo "✅ Added more hosts"
    else
        echo "✅ Sufficient hosts available: $host_count"
    fi
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
    
    oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOF'
from management.management.commands.utils import process_batch
from management.models import Principal

# Create Luke with limited access (is_admin=False)
try:
    process_batch([('12345', False, 'luke', '12350')])
    print('✅ Luke created successfully')
    
    # Verify Luke exists
    luke = Principal.objects.get(username='luke')
    print(f'Verified: Luke (ID: {luke.user_id})')
    
except Exception as e:
    print(f'Note: {e} (may already exist)')
    try:
        luke = Principal.objects.get(username='luke')
        print(f'Found existing Luke (ID: {luke.user_id})')
    except:
        print('❌ Failed to create or find Luke')

exit()
EOF" 2>/dev/null

    echo "✅ Luke user setup completed"
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
    timestamp=$(date +%s)
    local workspace_name="luke-workspace-$timestamp"
    
    local luke_host_ids_json
    luke_host_ids_json=$(printf '%s\n' "${luke_hosts[@]}" | jq -R . | jq -s .)
    
    echo "Creating workspace: $workspace_name"
    local workspace_response
    workspace_response=$(curl -s -X POST "http://localhost:8003/api/inventory/v1/groups" \
        -H "accept: application/json" \
        -H "Content-Type: application/json" \
        -H "x-rh-identity: $jdoe_header" \
        -d "{\"name\":\"$workspace_name\",\"host_ids\":$luke_host_ids_json}")
    
    if echo "$workspace_response" | jq -e '.id' >/dev/null 2>&1; then
        LUKE_WORKSPACE_UUID=$(echo "$workspace_response" | jq -r '.id')
        echo "✅ Luke's workspace created: $LUKE_WORKSPACE_UUID"
        echo "✅ 4 hosts assigned to Luke's workspace"
    else
        echo "❌ Failed to create Luke's workspace: $workspace_response"
        exit 1
    fi
}

# Setup RBAC permissions for Luke
setup_luke_rbac() {
    echo "🔐 Setting up RBAC permissions for Luke..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
from django.db import transaction
import json

try:
    with transaction.atomic():
        print('🔐 Setting up Luke RBAC permissions...')
        
        # Get Luke
        luke_principal = Principal.objects.get(username='luke')
        print(f'Found Luke: {luke_principal.username}')
        
        # Clear any existing policies for Luke
        old_policies = Policy.objects.filter(group__principals=luke_principal)
        for policy in old_policies:
            policy.group.principals.remove(luke_principal)
            print(f'Removed Luke from old policy: {policy.name}')
        
        # Create Luke's role
        luke_role, created = Role.objects.get_or_create(
            name='Luke Inventory Viewer',
            defaults={
                'display_name': 'Luke Inventory Viewer',
                'description': 'Luke\\'s personal inventory viewer role',
                'system': False,
                'platform_default': False,
                'admin_default': False,
                'tenant': luke_principal.tenant
            }
        )
        
        # Add inventory permissions to Luke's role
        inventory_permissions = ['inventory:hosts:read', 'inventory:groups:read']
        for perm_name in inventory_permissions:
            permission, created = Permission.objects.get_or_create(permission=perm_name)
            Access.objects.get_or_create(role=luke_role, permission=permission)
        
        print(f'Created/found Luke\\'s role: {luke_role.name}')
        
        # Create Luke's group and policy
        luke_group, created = Group.objects.get_or_create(
            name='luke-group',
            defaults={
                'tenant': luke_principal.tenant,
                'description': 'Luke\\'s access group'
            }
        )
        luke_group.principals.add(luke_principal)
        
        luke_policy, created = Policy.objects.get_or_create(
            name='luke-policy',
            defaults={
                'tenant': luke_principal.tenant,
                'description': 'Luke\\'s policy',
                'group': luke_group
            }
        )
        luke_policy.group = luke_group
        luke_policy.save()
        luke_policy.roles.add(luke_role)
        
        # Create ResourceDefinitions for workspace restriction
        luke_workspace_uuid = '$LUKE_WORKSPACE_UUID'
        print(f'Luke workspace UUID: {luke_workspace_uuid}')
        
        # Create ResourceDefinitions for each access object
        rd_count = 0
        for access in luke_role.access_set.all():
            if access.permission.permission.startswith('inventory:'):
                # Clear existing ResourceDefinitions
                ResourceDefinition.objects.filter(access=access).delete()
                
                # Create new ResourceDefinition
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
        
        print(f'\\n✅ Created {rd_count} ResourceDefinitions for Luke')
        print('✅ Luke is now restricted to his workspace only')
        
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()

exit()
EOFPYTHON" 2>/dev/null

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
            
            # Show workspace info
            local workspace_hosts
            workspace_hosts=$(echo "$response" | jq --arg workspace_id "$LUKE_WORKSPACE_UUID" '[.results[] | select(.groups[]?.id == $workspace_id)] | length')
            echo "📊 $workspace_hosts hosts are in Luke's workspace ($LUKE_WORKSPACE_UUID)"
            
            # Show host IDs
            echo "📋 Host IDs Luke can see:"
            echo "$response" | jq -r '.results[].id' | sed 's/^/   /'
            
        elif [[ "$host_count" -gt 4 ]]; then
            echo "⚠️  WARNING: Luke sees $host_count hosts (expected 4)"
            echo "   This suggests RBAC filtering may not be working correctly"
        else
            echo "❌ ERROR: Luke sees only $host_count hosts (expected 4)"
        fi
    else
        echo "❌ ERROR: Failed to get hosts for Luke"
        echo "Response: $response"
        return 1
    fi
    
    # Test workspace access
    echo ""
    echo "Testing Luke's workspace access..."
    local workspace_response
    workspace_response=$(curl -s -H "x-rh-identity: $luke_header" -H "Accept: application/json" "http://localhost:8002/api/inventory/v1/groups")
    
    if echo "$workspace_response" | jq -e '.results' >/dev/null 2>&1; then
        local workspace_count
        workspace_count=$(echo "$workspace_response" | jq '.results | length')
        echo "📊 Luke can see $workspace_count workspaces"
        
        if [[ "$workspace_count" -gt 0 ]]; then
            echo "📋 Workspaces Luke can see:"
            echo "$workspace_response" | jq -r '.results[] | "   - \(.name) (ID: \(.id), Hosts: \(.host_count // 0))"'
        fi
    else
        echo "❌ ERROR: Failed to get workspaces for Luke"
    fi
}

# Main execution
main() {
    check_prerequisites
    ensure_hosts
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
    if [[ -n "${LUKE_WORKSPACE_UUID:-}" ]]; then
        echo "🔗 Luke's workspace: $LUKE_WORKSPACE_UUID"
    fi
    echo ""
    echo "🧪 To test Luke's access again:"
    echo "   Run this script's test section or use the test_user_permissions.sh script"
    echo ""
    echo "📚 Luke should now only see 4 hosts in his assigned workspace!"
}

main "$@" 