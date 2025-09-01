"""
Client for interacting with the RBAC service.
"""

import json
import subprocess
from typing import Dict, List

from . import config

class RBACClient:
    """A client for interacting with the RBAC service via oc exec."""

    def __init__(self, namespace: str, rbac_pod: str):
        self.namespace = namespace
        self.rbac_pod = rbac_pod

    def _run_command(self, command: List[str], check=True, capture_output=True, text=True) -> subprocess.CompletedProcess:
        """Helper to run shell commands."""
        print(f"🔩 Running: {' '.join(command)}")
        return subprocess.run(command, check=check, capture_output=capture_output, text=text)

    def execute_rbac_script(self, script: str, description: str) -> str:
        """Execute a Python script inside the RBAC pod."""
        print(f"🔷 {description}...")
        command = f"./rbac/manage.py shell << 'EOF'\n{script}\nEOF"
        
        for attempt in range(config.MAX_RETRIES):
            result = self._run_command([
                'oc', 'exec', self.rbac_pod, '--container=rbac-service', '--', 'bash', '-c', command
            ], capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                print(f"   ✅ {description} completed successfully.")
                return result.stdout
            else:
                print(f"   ❌ {description} failed (attempt {attempt+1}/{config.MAX_RETRIES}).")
                print(f"   Stderr: {result.stderr}")
                if attempt == config.MAX_RETRIES - 1:
                    raise Exception(f"Failed to execute RBAC script for: {description}")
                time.sleep(2)
        return ""

    def setup_rbac_users_and_principals(self):
        """Create the demo users and ensure they exist as principals in RBAC."""
        users_batch = [
            ("12345", data['is_admin'], username, data['user_id'])
            for username, data in config.DEMO_USERS.items()
        ]
        
        script = f"""
from management.management.commands.utils import process_batch
from management.models import Principal
from django.db import transaction
import uuid

print("Processing demo users batch...")
users_to_process = {users_batch}

# Ensure jdoe tenant exists first
jdoe_principal = Principal.objects.filter(username="jdoe").first()
if not jdoe_principal:
    process_batch([("12345", True, "jdoe", "12345")])
    print("Created jdoe principal to establish tenant.")

jdoe_principal = Principal.objects.get(username="jdoe")
tenant = jdoe_principal.tenant

for org_id, is_admin, username, user_id in users_to_process:
    principal, created = Principal.objects.get_or_create(
        username=username,
        tenant=tenant,
        defaults={{
            "uuid": str(uuid.uuid4()),
            "type": "user",
            "user_id": user_id
        }}
    )
    if created:
        print(f"Created principal for {{username}}")
    else:
        print(f"Principal for {{username}} already exists.")
"""
        self.execute_rbac_script(script, "Creating demo users and principals")

    def create_rbac_structure(self):
        """Create the full RBAC structure of permissions, roles, groups, and policies."""
        script = f"""
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
from django.db import transaction

with transaction.atomic():
    jdoe = Principal.objects.get(username="jdoe")
    tenant = jdoe.tenant
    sara = Principal.objects.get(username="sara", tenant=tenant)
    alice = Principal.objects.get(username="alice", tenant=tenant)
    bob = Principal.objects.get(username="bob", tenant=tenant)
    
    print("Setting up permissions...")
    perms = {{
        name: Permission.objects.get_or_create(permission=perm)[0]
        for name, perm in {{
            "hosts_read": "inventory:hosts:read", "hosts_write": "inventory:hosts:write",
            "groups_read": "inventory:groups:read", "groups_write": "inventory:groups:write",
            "staleness_read": "staleness:staleness:read"
        }}.items()
    }}

    print("Setting up individual workspace roles for Alice and Bob...")
    alice_role, _ = Role.objects.update_or_create(
        name="Alice IT Team A Role", tenant=tenant,
        defaults={{"display_name": "Individual role for alice - IT Team A access", "description": "Individual role for alice - IT Team A access"}}
    )
    for p in [perms["hosts_read"], perms["hosts_write"], perms["groups_read"], perms["groups_write"]]:
        Access.objects.get_or_create(role=alice_role, permission=p, tenant=tenant)

    bob_role, _ = Role.objects.update_or_create(
        name="Bob IT Team B Role", tenant=tenant,
        defaults={{"display_name": "Individual role for bob - IT Team B access", "description": "Individual role for bob - IT Team B access"}}
    )
    for p in [perms["hosts_read"], perms["hosts_write"], perms["groups_read"], perms["groups_write"]]:
        Access.objects.get_or_create(role=bob_role, permission=p, tenant=tenant)

    print("Setting up support roles...")
    support_read_role, _ = Role.objects.update_or_create(
        name="Demo Global Host Viewer", tenant=tenant,
        defaults={{"display_name": "Demo Global Host Viewer", "description": "Read-only access to all hosts"}}
    )
    Access.objects.get_or_create(role=support_read_role, permission=perms["hosts_read"], tenant=tenant)
    
    support_write_role, _ = Role.objects.update_or_create(
        name="Demo Ungrouped Host Manager", tenant=tenant,
        defaults={{"display_name": "Demo Ungrouped Host Manager", "description": "Write access to ungrouped hosts"}}
    )
    for p in [perms["hosts_read"], perms["hosts_write"], perms["groups_read"], perms["groups_write"]]:
        Access.objects.get_or_create(role=support_write_role, permission=p, tenant=tenant)

    staleness_role, _ = Role.objects.update_or_create(
        name="Demo Staleness Reader", tenant=tenant,
        defaults={{"display_name": "Demo Staleness Reader", "description": "Read-only staleness access"}}
    )
    Access.objects.get_or_create(role=staleness_role, permission=perms["staleness_read"], tenant=tenant)

    print("Setting up individual groups and assigning users...")
    alice_group, _ = Group.objects.update_or_create(name="Alice Individual Group", tenant=tenant)
    alice_group.principals.set([alice])
    
    bob_group, _ = Group.objects.update_or_create(name="Bob Individual Group", tenant=tenant)
    bob_group.principals.set([bob])

    support_group, _ = Group.objects.update_or_create(name="Demo Support Team", tenant=tenant)
    support_group.principals.set([sara])
    
    default_group, _ = Group.objects.update_or_create(name="Demo Default Access", tenant=tenant)
    default_group.principals.set([jdoe, sara, alice, bob])

    print("Setting up individual workspace policies...")
    alice_policy, _ = Policy.objects.update_or_create(name="Alice IT Team A Policy", tenant=tenant, defaults={{"group": alice_group}})
    alice_policy.roles.set([alice_role])
    
    bob_policy, _ = Policy.objects.update_or_create(name="Bob IT Team B Policy", tenant=tenant, defaults={{"group": bob_group}})
    bob_policy.roles.set([bob_role])
    
    support_read_policy, _ = Policy.objects.update_or_create(name="Demo Support Global Read Policy", tenant=tenant, defaults={{"group": support_group}})
    support_read_policy.roles.set([support_read_role])
    
    support_write_policy, _ = Policy.objects.update_or_create(name="Demo Support Ungrouped Write Policy", tenant=tenant, defaults={{"group": support_group}})
    support_write_policy.roles.set([support_write_role])

    default_policy, _ = Policy.objects.update_or_create(name="Demo Default Staleness Policy", tenant=tenant, defaults={{"group": default_group}})
    default_policy.roles.set([staleness_role])
    
    print("RBAC structure created with individual workspace roles. Workspace connections will be made next.")
"""
        self.execute_rbac_script(script, "Creating RBAC structure with individual workspace roles")

    def create_admin_permissions(self):
        """Create admin permissions for jdoe to ensure full access."""
        script = f"""
from management.models import Principal, Role, Policy, Group, Access, Permission
from django.db import transaction

with transaction.atomic():
    jdoe = Principal.objects.get(username="jdoe")
    tenant = jdoe.tenant
    
    print("Setting up admin permissions for jdoe...")
    
    perms = {{}}
    permission_names = [
        "inventory:hosts:read", "inventory:hosts:write",
        "inventory:groups:read", "inventory:groups:write",
        "staleness:staleness:read", "staleness:staleness:write"
    ]
    
    for perm_name in permission_names:
        try:
            perm = Permission.objects.get(permission=perm_name)
            perms[perm_name] = perm
            print(f"Found permission: {{perm_name}}")
        except Permission.DoesNotExist:
            print(f"Permission not found: {{perm_name}}")

    jdoe_admin_role, _ = Role.objects.update_or_create(
        name="JDOE Admin Role", tenant=tenant,
        defaults={{"display_name": "Full admin role for jdoe", "description": "Complete admin access for demo admin user"}}
    )
    
    for perm in perms.values():
        Access.objects.get_or_create(role=jdoe_admin_role, permission=perm, tenant=tenant)

    jdoe_admin_group, _ = Group.objects.update_or_create(name="JDOE Admin Group", tenant=tenant)
    jdoe_admin_group.principals.set([jdoe])

    jdoe_admin_policy, _ = Policy.objects.update_or_create(name="JDOE Admin Policy", tenant=tenant, defaults={{"group": jdoe_admin_group}})
    jdoe_admin_policy.roles.set([jdoe_admin_role])
    
    print("✅ Created unrestricted admin permissions for jdoe")
"""
        self.execute_rbac_script(script, "Creating admin permissions for jdoe")

    def connect_workspaces_to_rbac(self, workspace_ids: Dict[str, str]):
        """Create ResourceDefinitions in RBAC to link policies to workspace UUIDs."""
        policy_map = {
            "Alice IT Team A Policy": workspace_ids["IT Team A"],
            "Bob IT Team B Policy": workspace_ids["IT Team B"],
        }

        script = f"""
from management.models import Policy, ResourceDefinition, Access
from django.db import transaction

policy_map = {json.dumps(policy_map)}
inventory_permissions = {json.dumps(config.INVENTORY_PERMISSIONS)}

print('🔧 INDIVIDUAL WORKSPACE-POLICY MAPPING:')
for policy_name, workspace_id in policy_map.items():
    print(f'   {{policy_name}} -> {{workspace_id}}')

with transaction.atomic():
    for policy_name, workspace_id in policy_map.items():
        try:
            policy = Policy.objects.get(name=policy_name)
            
            for role in policy.roles.all():
                for access in Access.objects.filter(role=role):
                    if access.permission.permission in inventory_permissions:
                        ResourceDefinition.objects.filter(access=access).delete()
                        
                        ResourceDefinition.objects.create(
                            access=access,
                            attributeFilter={{
                                'key': 'group.id', 
                                'operation': 'in', 
                                'value': [workspace_id]
                            }},
                            tenant=access.tenant
                        )
                        print(f"   ✅ Restricted {{access.permission.permission}} for {{role.name}} to workspace {{workspace_id}}")
            print(f"Connected individual policy '{{policy_name}}' to workspace '{{workspace_id}}'")
        except Policy.DoesNotExist:
            print(f"WARNING: Policy '{{policy_name}}' not found, skipping connection.")
"""
        self.execute_rbac_script(script, "Connecting workspaces to RBAC policies")
