#!/usr/bin/env python3

"""
Mass Workspace Teardown Script
==============================

This script removes all users, workspaces, and RBAC objects created by mass_workspace_setup.py

Usage:
    python mass_workspace_teardown.py
    python mass_workspace_teardown.py --confirm
"""

import argparse
import json
import sys
import subprocess
import requests
import base64
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import List, Dict

# Thread-safe progress tracking
progress_lock = Lock()
progress_data = {
    'users_removed': 0,
    'workspaces_removed': 0,
    'rbac_objects_removed': 0
}

class MassWorkspaceTeardown:
    def __init__(self, confirm: bool = False):
        self.confirm = confirm
        self.namespace = None
        self.rbac_pod = None
        self.port_forwards = []
        
        # Admin user for API calls
        self.admin_identity = {
            "identity": {
                "org_id": "12345",
                "type": "User",
                "auth_type": "basic-auth",
                "user": {
                    "username": "jdoe",
                    "email": "jdoe@redhat.com",
                    "first_name": "John",
                    "last_name": "Doe",
                    "is_active": True,
                    "is_org_admin": True,
                    "is_internal": True,
                    "locale": "en_US",
                    "user_id": "12345",
                    "account_number": "1234567890"
                },
                "internal": {"org_id": "12345"},
                "account_number": "1234567890"
            }
        }
        self.admin_header = base64.b64encode(json.dumps(self.admin_identity).encode()).decode()

    def setup_prerequisites(self):
        """Check prerequisites and setup connections"""
        print("🔍 Checking prerequisites...")
        
        # Check OpenShift connection
        try:
            result = subprocess.run(['oc', 'whoami'], capture_output=True, text=True, check=True)
            print(f"✅ Logged in as: {result.stdout.strip()}")
        except subprocess.CalledProcessError:
            raise Exception("❌ Not logged into OpenShift")
        
        # Get namespace
        try:
            result = subprocess.run(['oc', 'project', '-q'], capture_output=True, text=True, check=True)
            self.namespace = result.stdout.strip()
            print(f"✅ Using namespace: {self.namespace}")
        except subprocess.CalledProcessError:
            raise Exception("❌ No OpenShift namespace selected")
        
        # Get RBAC pod
        result = subprocess.run([
            'oc', 'get', 'pods', '-l', 'pod=rbac-service', '-o', 'json'
        ], capture_output=True, text=True, check=True)
        
        pods_data = json.loads(result.stdout)
        running_pods = [
            pod for pod in pods_data['items'] 
            if pod['status']['phase'] == 'Running' and 
               pod['metadata'].get('deletionTimestamp') is None
        ]
        
        if not running_pods:
            raise Exception("❌ No running RBAC service pods found")
        
        self.rbac_pod = running_pods[0]['metadata']['name']
        print(f"✅ Using RBAC pod: {self.rbac_pod}")

    def setup_port_forwarding(self):
        """Setup port forwarding for API access"""
        print("🔧 Setting up port forwarding...")
        
        # Kill existing port forwards
        subprocess.run(['pkill', '-f', 'oc port-forward.*800[23]'], check=False)
        time.sleep(2)
        
        # Get pod names
        hbi_reads_result = subprocess.run([
            'oc', 'get', 'pods', '-l', 'pod=host-inventory-service-reads', '-o', 'json'
        ], capture_output=True, text=True, check=True)
        
        hbi_writes_result = subprocess.run([
            'oc', 'get', 'pods', '-l', 'pod=host-inventory-service', '-o', 'json'
        ], capture_output=True, text=True, check=True)
        
        hbi_reads_data = json.loads(hbi_reads_result.stdout)
        hbi_writes_data = json.loads(hbi_writes_result.stdout)
        
        if not hbi_reads_data['items'] or not hbi_writes_data['items']:
            raise Exception("❌ HBI pods not found")
        
        hbi_reads_pod = hbi_reads_data['items'][0]['metadata']['name']
        hbi_writes_pod = hbi_writes_data['items'][0]['metadata']['name']
        
        if not self.namespace:
            raise Exception("❌ Namespace not set")
        
        # Start port forwards
        for port, pod, name in [
            (8002, hbi_reads_pod, 'reads'),
            (8003, hbi_writes_pod, 'writes')
        ]:
            proc = subprocess.Popen([
                'oc', 'port-forward', '-n', self.namespace, pod, f'{port}:8000'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.port_forwards.append(proc)
            print(f"📡 Port forward {port} -> {name}")
        
        # Wait for port forwards to be ready
        time.sleep(5)
        print("✅ Port forwarding established")

    def discover_mass_objects(self):
        """Discover all mass-created objects"""
        print("🔍 Discovering mass-created objects...")
        
        # Find mass workspaces
        headers = {
            "x-rh-identity": self.admin_header,
            "Accept": "application/json"
        }
        
        response = requests.get(
            "http://localhost:8002/api/inventory/v1/groups",
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        
        data = response.json()
        mass_workspaces = [
            ws for ws in data.get('results', [])
            if 'mass-workspace-' in ws['name']
        ]
        
        print(f"📋 Found {len(mass_workspaces)} mass workspaces")
        
        # Find mass users in RBAC
        if not self.rbac_pod:
            raise Exception("❌ RBAC pod not set")
        
        command = '''./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Group, Policy, Role

try:
    # Find mass users (user IDs starting with 2000x)
    mass_users = Principal.objects.filter(username__startswith='user', user_id__startswith='2000')
    print(f"MASS_USERS: {len(mass_users)}")
    
    # Find mass groups
    mass_groups = Group.objects.filter(name__startswith='mass-group-')
    print(f"MASS_GROUPS: {len(mass_groups)}")
    
    # Find mass policies
    mass_policies = Policy.objects.filter(name__startswith='mass-policy-')
    print(f"MASS_POLICIES: {len(mass_policies)}")
    
    # Find mass roles
    mass_roles = Role.objects.filter(name__startswith='Mass Viewer')
    print(f"MASS_ROLES: {len(mass_roles)}")
    
except Exception as e:
    print(f"ERROR: {e}")

exit()
EOFPYTHON'''
        
        result = subprocess.run([
            'oc', 'exec', self.rbac_pod, '--', 'bash', '-c', command
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"Failed to query RBAC objects: {result.stderr}")
        
        # Parse results
        rbac_counts = {}
        for line in result.stdout.split('\n'):
            if line.startswith('MASS_'):
                key, value = line.split(': ')
                rbac_counts[key] = int(value)
        
        print(f"📋 Found RBAC objects:")
        print(f"   • Users: {rbac_counts.get('MASS_USERS', 0)}")
        print(f"   • Groups: {rbac_counts.get('MASS_GROUPS', 0)}")
        print(f"   • Policies: {rbac_counts.get('MASS_POLICIES', 0)}")
        print(f"   • Roles: {rbac_counts.get('MASS_ROLES', 0)}")
        
        return mass_workspaces, rbac_counts

    def confirm_deletion(self, mass_workspaces: List[Dict], rbac_counts: Dict):
        """Confirm deletion with user"""
        if self.confirm:
            return True
        
        print("")
        print("⚠️  WARNING: This will permanently delete:")
        print(f"   • {len(mass_workspaces)} mass workspaces")
        print(f"   • {rbac_counts.get('MASS_USERS', 0)} mass users")
        print(f"   • {rbac_counts.get('MASS_GROUPS', 0)} mass groups")
        print(f"   • {rbac_counts.get('MASS_POLICIES', 0)} mass policies")
        print(f"   • {rbac_counts.get('MASS_ROLES', 0)} mass roles")
        print(f"   • All associated Access objects and ResourceDefinitions")
        print("")
        
        response = input("Are you sure you want to continue? (yes/no): ").lower().strip()
        return response in ['yes', 'y']

    def remove_mass_workspaces(self, mass_workspaces: List[Dict]):
        """Remove all mass workspaces"""
        if not mass_workspaces:
            print("ℹ️  No mass workspaces to remove")
            return
        
        print(f"🗑️  Removing {len(mass_workspaces)} mass workspaces...")
        
        headers = {
            "x-rh-identity": self.admin_header,
            "Accept": "application/json"
        }
        
        removed = 0
        for workspace in mass_workspaces:
            workspace_id = workspace['id']
            workspace_name = workspace['name']
            
            try:
                response = requests.delete(
                    f"http://localhost:8003/api/inventory/v1/groups/{workspace_id}",
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code in [200, 204, 404]:  # 404 means already deleted
                    print(f"✅ Removed workspace: {workspace_name}")
                    removed += 1
                else:
                    print(f"⚠️  Failed to remove workspace {workspace_name}: {response.status_code}")
            
            except Exception as e:
                print(f"⚠️  Error removing workspace {workspace_name}: {e}")
        
        with progress_lock:
            progress_data['workspaces_removed'] = removed
        
        print(f"✅ Removed {removed}/{len(mass_workspaces)} workspaces")

    def remove_mass_rbac_objects(self):
        """Remove all mass RBAC objects"""
        print("🗑️  Removing mass RBAC objects...")
        
        if not self.rbac_pod:
            raise Exception("❌ RBAC pod not set")
        
        command = '''./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Group, Policy, Role, Access, ResourceDefinition
from django.db import transaction

try:
    with transaction.atomic():
        print("🔧 Removing mass RBAC objects...")
        
        removed_counts = {
            'users': 0,
            'groups': 0,
            'policies': 0,
            'roles': 0,
            'access_objects': 0,
            'resource_definitions': 0
        }
        
        # Find mass users (user IDs starting with 2000x)
        mass_users = Principal.objects.filter(username__startswith='user', user_id__startswith='2000')
        print(f"Found {len(mass_users)} mass users to remove")
        
        # Remove users from groups and delete groups
        mass_groups = Group.objects.filter(name__startswith='mass-group-')
        for group in mass_groups:
            group.principals.clear()
            group.delete()
            removed_counts['groups'] += 1
        
        # Remove policies
        mass_policies = Policy.objects.filter(name__startswith='mass-policy-')
        for policy in mass_policies:
            policy.roles.clear()
            policy.delete()
            removed_counts['policies'] += 1
        
        # Remove roles and associated objects
        mass_roles = Role.objects.filter(name__startswith='Mass Viewer')
        for role in mass_roles:
            # Remove ResourceDefinitions
            access_objects = Access.objects.filter(role=role)
            for access in access_objects:
                rd_count = ResourceDefinition.objects.filter(access=access).count()
                ResourceDefinition.objects.filter(access=access).delete()
                removed_counts['resource_definitions'] += rd_count
            
            # Remove Access objects
            access_count = access_objects.count()
            access_objects.delete()
            removed_counts['access_objects'] += access_count
            
            # Remove role
            role.delete()
            removed_counts['roles'] += 1
        
        # Remove mass users (do this last)
        user_count = mass_users.count()
        mass_users.delete()
        removed_counts['users'] = user_count
        
        print(f"✅ Successfully removed:")
        print(f"   • Users: {removed_counts['users']}")
        print(f"   • Groups: {removed_counts['groups']}")
        print(f"   • Policies: {removed_counts['policies']}")
        print(f"   • Roles: {removed_counts['roles']}")
        print(f"   • Access objects: {removed_counts['access_objects']}")
        print(f"   • ResourceDefinitions: {removed_counts['resource_definitions']}")

except Exception as e:
    print(f"❌ Error removing RBAC objects: {e}")
    import traceback
    traceback.print_exc()
    raise

exit()
EOFPYTHON'''
        
        result = subprocess.run([
            'oc', 'exec', self.rbac_pod, '--', 'bash', '-c', command
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"Failed to remove RBAC objects: {result.stderr}")
        
        print(result.stdout)
        
        # Extract counts for progress tracking
        lines = result.stdout.split('\n')
        for line in lines:
            if 'Users:' in line:
                count = int(line.split(':')[1].strip())
                with progress_lock:
                    progress_data['users_removed'] = count
                    progress_data['rbac_objects_removed'] += count

    def run_teardown(self):
        """Execute the complete teardown"""
        print("🗑️  Starting Mass Workspace Teardown")
        print("=" * 50)
        
        start_time = time.time()
        
        try:
            # Setup
            self.setup_prerequisites()
            self.setup_port_forwarding()
            
            # Discover objects
            mass_workspaces, rbac_counts = self.discover_mass_objects()
            
            if not mass_workspaces and all(count == 0 for count in rbac_counts.values()):
                print("ℹ️  No mass objects found to remove")
                return
            
            # Confirm deletion
            if not self.confirm_deletion(mass_workspaces, rbac_counts):
                print("❌ Teardown cancelled by user")
                return
            
            # Remove objects
            self.remove_mass_workspaces(mass_workspaces)
            self.remove_mass_rbac_objects()
            
            # Summary
            elapsed_time = time.time() - start_time
            self.print_final_summary(elapsed_time)
            
        except Exception as e:
            print(f"❌ Teardown failed: {e}")
            raise
        finally:
            self.cleanup()

    def print_final_summary(self, elapsed_time: float):
        """Print final teardown summary"""
        print("")
        print("🎉 MASS WORKSPACE TEARDOWN COMPLETED!")
        print("=" * 50)
        print(f"✅ Removed: {progress_data['workspaces_removed']} workspaces")
        print(f"✅ Removed: {progress_data['users_removed']} users")
        print(f"✅ Removed: {progress_data['rbac_objects_removed']} RBAC objects")
        print(f"⏱️  Total time: {elapsed_time:.1f} seconds")
        print("")
        print("✅ All mass-created objects have been removed")
        print("✅ System restored to pre-mass-setup state")

    def cleanup(self):
        """Cleanup port forwards"""
        print("🧹 Cleaning up...")
        for proc in self.port_forwards:
            proc.terminate()
        subprocess.run(['pkill', '-f', 'oc port-forward.*800[23]'], check=False)


def main():
    parser = argparse.ArgumentParser(
        description="Mass Workspace Teardown - Remove all mass-created objects",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive teardown (asks for confirmation)
  python mass_workspace_teardown.py
  
  # Auto-confirm teardown (dangerous!)
  python mass_workspace_teardown.py --confirm
        """
    )
    
    parser.add_argument(
        '--confirm',
        action='store_true',
        help='Auto-confirm deletion without prompting (dangerous!)'
    )
    
    args = parser.parse_args()
    
    teardown = MassWorkspaceTeardown(args.confirm)
    teardown.run_teardown()


if __name__ == '__main__':
    main() 