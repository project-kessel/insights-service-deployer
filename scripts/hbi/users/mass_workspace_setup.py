#!/usr/bin/env python3

"""
Mass Workspace Setup Script
===========================

This script creates a user-defined number of users/workspaces and distributes
a large number of hosts across them for demo purposes.

Usage:
    python mass_workspace_setup.py --users 20 --hosts 10000 --ungrouped-ratio 0.1

Features:
- Creates N users and N workspaces (1:1 mapping)
- Distributes hosts evenly across workspaces
- Leaves a percentage of hosts ungrouped
- Parallel processing for performance
- Progress tracking and error handling
- Batch API operations where possible
"""

import argparse
import json
import sys
import time
import subprocess
import requests
import base64
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import math
from typing import List, Dict, Tuple, Optional

# Global configuration
API_TIMEOUT = 30
MAX_RETRIES = 3
BATCH_SIZE = 50
MAX_WORKERS = 5

# Thread-safe progress tracking
progress_lock = Lock()
progress_data = {
    'users_created': 0,
    'workspaces_created': 0,
    'hosts_assigned': 0,
    'rbac_objects_created': 0
}

class MassWorkspaceSetup:
    def __init__(self, num_users: int, num_hosts: int, ungrouped_ratio: float):
        self.num_users = num_users
        self.num_hosts = num_hosts
        self.ungrouped_ratio = ungrouped_ratio
        self.namespace = None
        self.rbac_pod = None
        self.port_forwards = []
        
        # Calculate distribution
        self.hosts_to_assign = int(num_hosts * (1 - ungrouped_ratio))
        self.hosts_per_workspace = self.hosts_to_assign // num_users
        self.remainder_hosts = self.hosts_to_assign % num_users
        
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
            if not self.namespace:
                raise subprocess.CalledProcessError(1, 'oc project -q')
            print(f"✅ Using namespace: {self.namespace}")
        except subprocess.CalledProcessError:
            # Get available projects to help user
            try:
                projects_result = subprocess.run(['oc', 'get', 'projects', '--no-headers'], capture_output=True, text=True)
                if projects_result.returncode == 0 and projects_result.stdout.strip():
                    available_projects = [line.split()[0] for line in projects_result.stdout.strip().split('\n')]
                    ephemeral_projects = [p for p in available_projects if 'ephemeral' in p]
                    
                    print("❌ ERROR: No OpenShift namespace selected")
                    print("\n📋 Available projects:")
                    for project in available_projects[:10]:  # Show first 10
                        print(f"   • {project}")
                    
                    if ephemeral_projects:
                        print(f"\n🎯 Suggested ephemeral projects:")
                        for project in ephemeral_projects:
                            print(f"   • {project}")
                        print(f"\n💡 Try: oc project {ephemeral_projects[0]}")
                    else:
                        print(f"\n💡 Try: oc project <project-name>")
                else:
                    print("❌ ERROR: No OpenShift namespace selected and cannot list projects")
            except:
                print("❌ ERROR: No OpenShift namespace selected")
                print("💡 Try: oc project <your-namespace>")
            
            raise Exception("❌ No OpenShift namespace selected")
        
        # Check services are running
        self._check_service_running('rbac-service')
        self._check_service_running('host-inventory-service')
        
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

    def _check_service_running(self, service: str):
        """Check if a service is running"""
        result = subprocess.run([
            'oc', 'get', 'pods', '-l', f'pod={service}', '--no-headers'
        ], capture_output=True, text=True)
        
        if result.returncode != 0 or 'Running' not in result.stdout:
            raise Exception(f"❌ {service} not running")

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

    def get_available_hosts(self) -> List[str]:
        """Get all available host IDs"""
        print(f"📡 Fetching {self.num_hosts} available hosts...")
        
        url = "http://localhost:8002/api/inventory/v1/hosts"
        headers = {
            "x-rh-identity": self.admin_header,
            "Accept": "application/json"
        }
        
        # Handle pagination to get all hosts
        all_hosts = []
        page = 1
        per_page = 100
        
        while len(all_hosts) < self.num_hosts:
            params = {
                'page': page,
                'per_page': min(per_page, self.num_hosts - len(all_hosts))
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=API_TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            hosts = [host['id'] for host in data.get('results', [])]
            all_hosts.extend(hosts)
            
            if len(hosts) < per_page:  # Last page
                break
                
            page += 1
            
            if page % 10 == 0:
                print(f"   Fetched {len(all_hosts)} hosts so far...")
        
        if len(all_hosts) < self.num_hosts:
            raise Exception(f"❌ Only {len(all_hosts)} hosts available, need {self.num_hosts}")
        
        selected_hosts = all_hosts[:self.num_hosts]
        print(f"✅ Selected {len(selected_hosts)} hosts for distribution")
        return selected_hosts

    def calculate_host_distribution(self, host_ids: List[str]) -> Tuple[List[str], Dict[int, List[str]]]:
        """Calculate how to distribute hosts across workspaces"""
        print("📊 Calculating host distribution...")
        
        # Hosts to leave ungrouped
        ungrouped_count = int(len(host_ids) * self.ungrouped_ratio)
        ungrouped_hosts = host_ids[:ungrouped_count]
        
        # Hosts to distribute
        hosts_to_distribute = host_ids[ungrouped_count:]
        
        # Distribution algorithm
        workspace_assignments = {}
        host_index = 0
        
        for workspace_num in range(self.num_users):
            # Base allocation
            hosts_for_this_workspace = self.hosts_per_workspace
            
            # Add remainder host to first N workspaces
            if workspace_num < self.remainder_hosts:
                hosts_for_this_workspace += 1
            
            # Assign hosts
            workspace_hosts = hosts_to_distribute[host_index:host_index + hosts_for_this_workspace]
            workspace_assignments[workspace_num] = workspace_hosts
            host_index += hosts_for_this_workspace
        
        print(f"📋 Distribution plan:")
        print(f"   • Ungrouped hosts: {len(ungrouped_hosts)}")
        print(f"   • Hosts per workspace: {self.hosts_per_workspace}")
        print(f"   • Workspaces with +1 host: {self.remainder_hosts}")
        
        return ungrouped_hosts, workspace_assignments

    def create_user_batch(self, user_numbers: List[int]) -> int:
        """Create a batch of users in RBAC using the robust two-step approach"""
        if not self.rbac_pod:
            raise Exception("❌ RBAC pod not set")
        
        created_count = 0
        
        for user_num in user_numbers:
            user_id = str(20000 + user_num)
            username = f"user{user_num}"
            
            # Create individual user using the Luke script approach
            command = f'''./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, ExtTenant
from management.management.commands.utils import process_batch
import uuid

try:
    # Step 1: Check if user already exists
    try:
        existing_user = Principal.objects.get(username='{username}')
        print(f"✅ User {username} already exists (ID: {{existing_user.user_id}})")
    except Principal.DoesNotExist:
        # Step 2: Create tenant and user via process_batch (like rbac_seed_users.sh)
        print(f"Creating tenant and user via process_batch for {username}...")
        process_batch([("12345", False, "{username}", "{user_id}")])
        print("BATCH_COMPLETED")
        
        # Step 3: Manually create Principal entry (like Luke script does)
        print(f"Creating Principal entry for {username}...")
        
        # Get the tenant ID for org_id 12345
        from api.models import Tenant
        tenant = Tenant.objects.get(org_id="12345")
        print(f"Found tenant: {{tenant.id}}")
        
        # Create Principal entry manually
        user_uuid = str(uuid.uuid4())
        principal = Principal.objects.create(
            uuid=user_uuid,
            username="{username}",
            tenant_id=tenant.id,
            type="user",
            user_id="{user_id}"
        )
        print(f"✅ PRINCIPAL_CREATED: {{principal.username}} (ID: {{principal.user_id}})")
    
    # Step 4: Verify user was created successfully
    user = Principal.objects.get(username="{username}")
    print(f"✅ VERIFIED: User {{user.username}} exists (ID: {{user.user_id}}, tenant: {{user.tenant}})")

except Exception as e:
    print(f"❌ Error creating user {username}: {{e}}")
    # Try to find user anyway in case of partial creation
    try:
        user = Principal.objects.get(username="{username}")
        print(f"✅ FOUND_EXISTING: {{user.username}} (ID: {{user.user_id}})")
    except Principal.DoesNotExist:
        print(f"❌ CREATION_FAILED: User {username} not found")
        raise Exception(f"User {username} not created")

exit()
EOFPYTHON'''
            
            result = subprocess.run([
                'oc', 'exec', self.rbac_pod, '--', 'bash', '-c', command
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"❌ Failed to create user {username}: {result.stderr}")
                raise Exception(f"Failed to create user {username}: {result.stderr}")
            
            # Check if user was actually created or found
            if any(keyword in result.stdout for keyword in ["PRINCIPAL_CREATED", "FOUND_EXISTING", "already exists", "VERIFIED"]):
                created_count += 1
                print(f"✅ User {username} processed successfully")
            else:
                print(f"❌ User {username} creation failed")
                print(f"Output: {result.stdout}")
                print(f"Error: {result.stderr}")
                raise Exception(f"Failed to create user {username}")
        
        with progress_lock:
            progress_data['users_created'] += created_count
        
        return created_count

    def create_workspace_batch(self, workspace_assignments: Dict[int, List[str]], start_idx: int, batch_size: int) -> int:
        """Create a batch of workspaces and assign hosts"""
        created = 0
        
        for i in range(start_idx, min(start_idx + batch_size, len(workspace_assignments))):
            workspace_num = list(workspace_assignments.keys())[i]
            host_ids = workspace_assignments[workspace_num]
            
            if not host_ids:
                continue
            
            # Create workspace
            workspace_name = f"mass-workspace-{workspace_num}-{int(time.time())}"
            
            payload = {
                "name": workspace_name,
                "host_ids": host_ids
            }
            
            headers = {
                "x-rh-identity": self.admin_header,
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                "http://localhost:8003/api/inventory/v1/groups",
                json=payload,
                headers=headers,
                timeout=API_TIMEOUT
            )
            
            if response.status_code not in [200, 201]:
                print(f"⚠️  Failed to create workspace {workspace_num}: {response.text}")
                continue
            
            workspace_data = response.json()
            workspace_uuid = workspace_data['id']
            
            # Create RBAC setup for this workspace
            self._create_rbac_for_workspace(workspace_num, workspace_uuid)
            
            created += 1
            
            with progress_lock:
                progress_data['workspaces_created'] += 1
                progress_data['hosts_assigned'] += len(host_ids)
        
        return created

    def _create_rbac_for_workspace(self, user_num: int, workspace_uuid: str):
        """Create RBAC objects for a single workspace"""
        user_id = str(20000 + user_num)
        username = f"user{user_num}"
        
        command = f'''./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Role, Policy, Group, Access, Permission, ResourceDefinition
from django.db import transaction

try:
    with transaction.atomic():
        # Get user
        user_principal = Principal.objects.get(username="{username}")
        tenant = user_principal.tenant
        
        # Create group
        group = Group.objects.create(
            name='mass-group-{user_num}',
            tenant=tenant,
            description='Mass demo group for {username}'
        )
        
        # Create role
        role = Role.objects.create(
            name='Mass Viewer {user_num}',
            display_name='Mass Viewer {user_num}',
            description='Mass demo viewer role',
            system=False,
            platform_default=False,
            admin_default=False,
            tenant=tenant
        )
        
        # Add permissions
        for perm_name in ['inventory:hosts:read', 'inventory:groups:read']:
            permission, _ = Permission.objects.get_or_create(permission=perm_name)
            access = Access.objects.create(
                role=role,
                permission=permission,
                tenant=tenant
            )
            
            # Create ResourceDefinition
            ResourceDefinition.objects.create(
                access=access,
                tenant=tenant,
                attributeFilter={{
                    'key': 'group.id',
                    'operation': 'in',
                    'value': ['{workspace_uuid}']
                }}
            )
        
        # Create policy
        policy = Policy.objects.create(
            name='mass-policy-{user_num}',
            tenant=tenant,
            description='Mass demo policy',
            group=group
        )
        
        # Add user to group and role to policy
        group.principals.add(user_principal)
        policy.roles.add(role)
        
        print(f"✅ RBAC setup complete for {username}")
        
except Exception as e:
    print(f"❌ Error creating RBAC for {username}: {{e}}")
    raise

exit()
EOFPYTHON'''
        
        if not self.rbac_pod:
            raise Exception("❌ RBAC pod not set")
        
        result = subprocess.run([
            'oc', 'exec', self.rbac_pod, '--', 'bash', '-c', command
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"Failed to create RBAC for user{user_num}: {result.stderr}")
        
        with progress_lock:
            progress_data['rbac_objects_created'] += 6  # group + role + policy + 2 access + 2 resource definitions

    def _verify_users_exist(self):
        """Verify that all users exist in RBAC before proceeding"""
        if not self.rbac_pod:
            raise Exception("❌ RBAC pod not set")
        
        command = f'''./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal

try:
    print("🔍 Checking for mass-created users...")
    
    # Check total principals
    total_principals = Principal.objects.count()
    print(f"Total principals in database: {{total_principals}}")
    
    # Check for our specific users
    missing_users = []
    found_users = []
    
    for i in range({self.num_users}):
        username = f"user{{i}}"
        user_id = str(20000 + i)
        
        try:
            user = Principal.objects.get(username=username)
            found_users.append(username)
            print(f"✅ User {{username}} exists (ID: {{user.user_id}}, tenant: {{user.tenant}})")
        except Principal.DoesNotExist:
            missing_users.append(username)
            print(f"❌ User {{username}} missing")
    
    print(f"\\nSummary:")
    print(f"  Found: {{len(found_users)}} users")
    print(f"  Missing: {{len(missing_users)}} users")
    
    if missing_users:
        print(f"\\n❌ Missing users: {{missing_users}}")
        
        # Try to understand why users are missing
        print("\\n🔍 Debugging - checking for any users with similar patterns...")
        similar_users = Principal.objects.filter(username__startswith='user').values_list('username', 'user_id')
        if similar_users:
            print("Found similar users:")
            for username, user_id in similar_users:
                print(f"  - {{username}} (ID: {{user_id}})")
        else:
            print("No users with 'user' prefix found")
        
        # Check for users with our expected user IDs
        expected_user_ids = [str(20000 + i) for i in range({self.num_users})]
        users_with_expected_ids = Principal.objects.filter(user_id__in=expected_user_ids).values_list('username', 'user_id')
        if users_with_expected_ids:
            print("\\nUsers with expected IDs but different usernames:")
            for username, user_id in users_with_expected_ids:
                print(f"  - {{username}} (ID: {{user_id}})")
        
        raise Exception(f"Users not found: {{missing_users}}")
    else:
        print(f"\\n✅ All {{len(found_users)}} users verified successfully")

except Exception as e:
    print(f"❌ Verification failed: {{e}}")
    raise

exit()
EOFPYTHON'''
        
        result = subprocess.run([
            'oc', 'exec', self.rbac_pod, '--', 'bash', '-c', command
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"❌ User verification failed: {result.stderr}")
            print(f"❌ Output: {result.stdout}")
            raise Exception("User verification failed")
        
        print(result.stdout)

    def run_mass_setup(self):
        """Execute the complete mass setup"""
        print(f"🚀 Starting Mass Workspace Setup")
        print(f"=" * 50)
        print(f"Users/Workspaces: {self.num_users}")
        print(f"Total Hosts: {self.num_hosts}")
        print(f"Ungrouped Ratio: {self.ungrouped_ratio:.1%}")
        print(f"Hosts per Workspace: {self.hosts_per_workspace}")
        print(f"Remainder Hosts: {self.remainder_hosts}")
        print("")
        
        start_time = time.time()
        
        try:
            # Setup
            self.setup_prerequisites()
            self.setup_port_forwarding()
            
            # Get hosts
            host_ids = self.get_available_hosts()
            ungrouped_hosts, workspace_assignments = self.calculate_host_distribution(host_ids)
            
            # Create users in batches
            print(f"👥 Creating {self.num_users} users in batches...")
            user_batches = [
                list(range(i, min(i + BATCH_SIZE, self.num_users)))
                for i in range(0, self.num_users, BATCH_SIZE)
            ]
            
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(self.create_user_batch, batch) for batch in user_batches]
                for future in as_completed(futures):
                    future.result()
            
            print(f"✅ All {self.num_users} users created")
            
            # Wait a moment for all users to be fully created in RBAC
            print("⏳ Waiting for user creation to complete...")
            time.sleep(5)
            
            # Verify all users exist before proceeding
            print("🔍 Verifying all users exist in RBAC...")
            self._verify_users_exist()
            
            # Create workspaces and RBAC in batches
            print(f"🏗️  Creating {self.num_users} workspaces and assigning hosts...")
            
            workspace_batches = [
                (i, min(BATCH_SIZE, len(workspace_assignments) - i))
                for i in range(0, len(workspace_assignments), BATCH_SIZE)
            ]
            
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [
                    executor.submit(self.create_workspace_batch, workspace_assignments, start_idx, batch_size)
                    for start_idx, batch_size in workspace_batches
                ]
                
                for future in as_completed(futures):
                    future.result()
            
            # Progress summary
            elapsed_time = time.time() - start_time
            self.print_final_summary(elapsed_time, ungrouped_hosts)
            
        except Exception as e:
            print(f"❌ Mass setup failed: {e}")
            raise
        finally:
            self.cleanup()

    def print_progress(self):
        """Print current progress"""
        with progress_lock:
            print(f"Progress: Users: {progress_data['users_created']}/{self.num_users}, "
                  f"Workspaces: {progress_data['workspaces_created']}/{self.num_users}, "
                  f"Hosts: {progress_data['hosts_assigned']}/{self.hosts_to_assign}, "
                  f"RBAC Objects: {progress_data['rbac_objects_created']}")

    def print_final_summary(self, elapsed_time: float, ungrouped_hosts: List[str]):
        """Print final setup summary"""
        print("")
        print("🎉 MASS WORKSPACE SETUP COMPLETED!")
        print("=" * 50)
        print(f"✅ Created: {progress_data['users_created']} users")
        print(f"✅ Created: {progress_data['workspaces_created']} workspaces")
        print(f"✅ Assigned: {progress_data['hosts_assigned']} hosts to workspaces")
        print(f"✅ Left ungrouped: {len(ungrouped_hosts)} hosts")
        print(f"✅ Created: {progress_data['rbac_objects_created']} RBAC objects")
        print(f"⏱️  Total time: {elapsed_time:.1f} seconds")
        print(f"📊 Rate: {progress_data['hosts_assigned'] / elapsed_time:.1f} hosts/second")
        print("")
        print("🧪 Test individual user access:")
        print("   python test_mass_permissions.py --user 5")
        print("")
        print("🗑️  To cleanup:")
        print("   python mass_workspace_teardown.py")

    def cleanup(self):
        """Cleanup port forwards"""
        print("🧹 Cleaning up...")
        for proc in self.port_forwards:
            proc.terminate()
        subprocess.run(['pkill', '-f', 'oc port-forward.*800[23]'], check=False)


def main():
    parser = argparse.ArgumentParser(
        description="Mass Workspace Setup - Create many users/workspaces with host distribution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create 20 users/workspaces with 10,000 hosts (10% ungrouped)
  python mass_workspace_setup.py --users 20 --hosts 10000
  
  # Create 50 users/workspaces with 5,000 hosts (20% ungrouped)  
  python mass_workspace_setup.py --users 50 --hosts 5000 --ungrouped-ratio 0.2
        """
    )
    
    parser.add_argument(
        '--users',
        type=int,
        required=True,
        help='Number of users and workspaces to create (1:1 mapping)'
    )
    
    parser.add_argument(
        '--hosts',
        type=int,
        required=True,
        help='Total number of hosts to distribute'
    )
    
    parser.add_argument(
        '--ungrouped-ratio',
        type=float,
        default=0.1,
        help='Ratio of hosts to leave ungrouped (default: 0.1 = 10%%)'
    )
    
    args = parser.parse_args()
    
    # Validation
    if args.users <= 0:
        print("❌ ERROR: Number of users must be positive")
        sys.exit(1)
    
    if args.hosts <= 0:
        print("❌ ERROR: Number of hosts must be positive")
        sys.exit(1)
    
    if not 0 <= args.ungrouped_ratio <= 1:
        print("❌ ERROR: Ungrouped ratio must be between 0 and 1")
        sys.exit(1)
    
    if args.hosts < args.users:
        print("❌ ERROR: Must have at least 1 host per user")
        sys.exit(1)
    
    # Run setup
    setup = MassWorkspaceSetup(args.users, args.hosts, args.ungrouped_ratio)
    setup.run_mass_setup()


if __name__ == '__main__':
    main() 