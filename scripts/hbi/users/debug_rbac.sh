#!/bin/bash

set -e

echo "🔍 RBAC Debug - Luke and Leia Permissions"
echo "=========================================="
echo ""

# Check prerequisites
check_prerequisites() {
    if ! oc whoami >/dev/null 2>&1; then
        echo "❌ ERROR: Not logged into OpenShift"
        exit 1
    fi
    
    if ! oc get pods -l pod=rbac-service --no-headers 2>/dev/null | grep -q Running; then
        echo "❌ ERROR: RBAC service not running"
        exit 1
    fi
    
    echo "✅ Prerequisites check passed"
    echo ""
}

# Debug RBAC configuration
debug_rbac() {
    echo "🔍 Debugging RBAC configuration..."
    
    local rbac_pod
    rbac_pod=$(oc get pods -l pod=rbac-service -o json | jq -r '.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null) | .metadata.name' | head -n 1)
    
    oc exec "$rbac_pod" -- bash -c "./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
import json

print('🔍 RBAC Configuration Debug')
print('==========================')

# Check Luke
print('\\n👤 LUKE CONFIGURATION:')
try:
    luke = Principal.objects.get(username='luke')
    print(f'Found Luke: {luke.username} (ID: {luke.user_id})')
    
    # Check Luke's groups
    luke_groups = Group.objects.filter(principals=luke)
    print(f'Luke is in {luke_groups.count()} groups:')
    for group in luke_groups:
        print(f'  - {group.name} (platform_default: {getattr(group, \"platform_default\", \"N/A\")})')
    
    # Check Luke's policies
    luke_policies = Policy.objects.filter(group__principals=luke)
    print(f'Luke has {luke_policies.count()} policies:')
    for policy in luke_policies:
        print(f'  - {policy.name}')
        for role in policy.roles.all():
            print(f'    Role: {role.name}')
            for access in Access.objects.filter(role=role):
                print(f'      Permission: {access.permission.permission}')
                rds = ResourceDefinition.objects.filter(access=access)
                if rds.exists():
                    for rd in rds:
                        if rd.attributeFilter:
                            try:
                                filter_data = json.loads(rd.attributeFilter) if isinstance(rd.attributeFilter, str) else rd.attributeFilter
                                print(f'        ResourceDefinition: {filter_data}')
                            except:
                                print(f'        ResourceDefinition: {rd.attributeFilter}')
                        else:
                            print(f'        ResourceDefinition: No filter')
                else:
                    print(f'        ResourceDefinition: None (UNRESTRICTED)')
    
except Principal.DoesNotExist:
    print('❌ Luke not found')

# Check Leia
print('\\n👤 LEIA CONFIGURATION:')
try:
    leia = Principal.objects.get(username='leia')
    print(f'Found Leia: {leia.username} (ID: {leia.user_id})')
    
    # Check Leia's groups
    leia_groups = Group.objects.filter(principals=leia)
    print(f'Leia is in {leia_groups.count()} groups:')
    for group in leia_groups:
        print(f'  - {group.name} (platform_default: {getattr(group, \"platform_default\", \"N/A\")})')
    
    # Check Leia's policies
    leia_policies = Policy.objects.filter(group__principals=leia)
    print(f'Leia has {leia_policies.count()} policies:')
    for policy in leia_policies:
        print(f'  - {policy.name}')
        for role in policy.roles.all():
            print(f'    Role: {role.name}')
            for access in Access.objects.filter(role=role):
                print(f'      Permission: {access.permission.permission}')
                rds = ResourceDefinition.objects.filter(access=access)
                if rds.exists():
                    for rd in rds:
                        if rd.attributeFilter:
                            try:
                                filter_data = json.loads(rd.attributeFilter) if isinstance(rd.attributeFilter, str) else rd.attributeFilter
                                print(f'        ResourceDefinition: {filter_data}')
                            except:
                                print(f'        ResourceDefinition: {rd.attributeFilter}')
                        else:
                            print(f'        ResourceDefinition: No filter')
                else:
                    print(f'        ResourceDefinition: None (UNRESTRICTED)')
    
except Principal.DoesNotExist:
    print('❌ Leia not found')

# Check Default Access group
print('\\n🔍 DEFAULT ACCESS GROUP:')
try:
    default_group = Group.objects.get(name='Default access')
    print(f'Found Default access group: {default_group.name}')
    
    # Check who's in the default group
    default_principals = default_group.principals.all()
    print(f'Default group has {default_principals.count()} principals:')
    for principal in default_principals:
        print(f'  - {principal.username} (ID: {principal.user_id})')
    
    # Check default group policies
    default_policies = Policy.objects.filter(group=default_group)
    print(f'Default group has {default_policies.count()} policies:')
    for policy in default_policies:
        print(f'  - {policy.name}')
        for role in policy.roles.all():
            print(f'    Role: {role.name}')
            for access in Access.objects.filter(role=role):
                if access.permission.permission.startswith('inventory:'):
                    print(f'      INVENTORY Permission: {access.permission.permission}')
                    rds = ResourceDefinition.objects.filter(access=access)
                    if rds.exists():
                        for rd in rds:
                            if rd.attributeFilter:
                                try:
                                    filter_data = json.loads(rd.attributeFilter) if isinstance(rd.attributeFilter, str) else rd.attributeFilter
                                    print(f'        ResourceDefinition: {filter_data}')
                                except:
                                    print(f'        ResourceDefinition: {rd.attributeFilter}')
                            else:
                                print(f'        ResourceDefinition: No filter')
                    else:
                        print(f'        ResourceDefinition: None (UNRESTRICTED) ⚠️')
    
except Group.DoesNotExist:
    print('❌ Default access group not found')

print('\\n🔍 SUMMARY:')
print('============')
print('If users are seeing all hosts, check for:')
print('1. Users in \"Default access\" group with unrestricted permissions')
print('2. Permissions without ResourceDefinitions (unrestricted)')
print('3. RBAC bypass configuration')

exit()
EOFPYTHON" 2>/dev/null
}

# Main execution
main() {
    check_prerequisites
    debug_rbac
}

main "$@" 