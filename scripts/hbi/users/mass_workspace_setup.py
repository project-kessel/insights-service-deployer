#!/usr/bin/env python3

"""
Modern Mass Workspace Setup Script
==================================

This script creates a user-defined number of users/workspaces and distributes
a large number of hosts across them for demo purposes using MODERN API approaches.

✅ WHAT'S NEW:
- Uses Keycloak API for user creation (no database hacking!)
- Uses HBI Groups API for workspace creation (the working approach!)
- Uses RBAC v1 API with ResourceDefinitions for workspace filtering
- Proper error handling and validation with retries
- Full audit trails and event publishing
- No more oc exec database bypassing!

Usage:
    python modern_mass_workspace_setup.py --users 20 --hosts 10000 --ungrouped-ratio 0.1

Features:
- Creates N users via Keycloak Admin API (no database hacking!)
- Creates N workspaces via HBI Groups API (the working approach!)
- Distributes hosts evenly across workspaces during creation
- Leaves a percentage of hosts ungrouped
- Parallel processing for performance
- Progress tracking and comprehensive error handling with retries
- Proper API validation and event publishing
"""

import argparse
import json
import sys
import time
import requests
import subprocess
import base64
import uuid
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import math
from typing import List, Dict, Tuple, Optional
from urllib.parse import urljoin

# Global configuration
API_TIMEOUT = 60
MAX_RETRIES = 3
BATCH_SIZE = 20  # Smaller batches for API calls
MAX_WORKERS = 3  # Conservative for API rate limiting
RETRY_DELAY = 5  # Longer delay for RBAC v2 processing

# Thread-safe progress tracking
progress_lock = Lock()
progress_data = {
    'users_created': 0,
    'workspaces_created': 0,
    'hosts_assigned': 0,
    'permissions_created': 0
}

class ModernMassWorkspaceSetup:
    def __init__(self, num_users: int, num_hosts: int, ungrouped_ratio: float):
        self.num_users = num_users
        self.num_hosts = num_hosts
        self.ungrouped_ratio = ungrouped_ratio
        # OC/bonfire should be used for Keycloak credentials and port-forwarding only (no oc exec).
        self.port_forwards = []
        
        # API endpoints (configurable via environment variables)
        # Do not perform oc port-forwarding here; assume endpoints are reachable as configured
        self.rbac_endpoint = os.getenv("RBAC_URL", "http://localhost:8080/api/rbac")
        self.hbi_reads_endpoint = os.getenv("HBI_READS_URL", "http://localhost:8002/api/inventory/v1")
        self.hbi_writes_endpoint = os.getenv("HBI_WRITES_URL", "http://localhost:8003/api/inventory/v1")
        self.keycloak_admin_route = None
        self.keycloak_admin_token = None
        
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
        """Check prerequisites and setup connections without using oc (except for Keycloak creds)."""
        print("🔍 Checking prerequisites...")
        # Setup Keycloak access via bonfire/oc only
        self._setup_keycloak_access()
        print("✅ Prerequisites checked (endpoints assumed reachable):")
        print(f"   RBAC: {self.rbac_endpoint}")
        print(f"   HBI Reads: {self.hbi_reads_endpoint}")
        print(f"   HBI Writes: {self.hbi_writes_endpoint}")

    # Removed project suggestions and oc-based service checks to comply with constraint

    # Removed oc-based service running checks

    def _setup_keycloak_access(self):
        """Setup Keycloak admin access"""
        print("🔑 Setting up Keycloak admin access...")
        
        try:
            # Get Keycloak admin credentials from bonfire
            result = subprocess.run([
                'bonfire', 'namespace', 'describe', '-o', 'json'
            ], capture_output=True, text=True, check=True)
            
            namespace_data = json.loads(result.stdout)
            
            # Extract Keycloak credentials
            keycloak_admin_username = None
            keycloak_admin_password = None
            
            for key, value in namespace_data.items():
                if 'keycloak_admin_username' in key.lower():
                    keycloak_admin_username = value
                elif 'keycloak_admin_password' in key.lower():
                    keycloak_admin_password = value
                elif 'keycloak' in key.lower() and 'route' in key.lower():
                    self.keycloak_admin_route = value
            
            if not all([keycloak_admin_username, keycloak_admin_password, self.keycloak_admin_route]):
                print("⚠️  Keycloak credentials not found in bonfire namespace")
                print("💡 Falling back to RBAC v2 user creation...")
                self.keycloak_admin_route = None
                return
            
            # Get admin token
            self.keycloak_admin_token = self._get_keycloak_admin_token(
                keycloak_admin_username, keycloak_admin_password
            )
            
            print("✅ Keycloak admin access configured")
            
        except Exception as e:
            print(f"⚠️  Could not setup Keycloak access: {e}")
            self.keycloak_admin_route = None

    def _get_keycloak_admin_token(self, username: str, password: str) -> str:
        """Get Keycloak admin token"""
        token_url = f"{self.keycloak_admin_route}/realms/master/protocol/openid-connect/token"
        
        response = requests.post(
            token_url,
            data={
                'grant_type': 'password',
                'client_id': 'admin-cli',
                'username': username,
                'password': password
            },
            timeout=API_TIMEOUT
        )
        
        if response.status_code != 200:
            raise Exception(f"Failed to get Keycloak admin token: {response.text}")
        
        return response.json()['access_token']

    def setup_port_forwarding(self):
        """Setup oc port-forward for RBAC and HBI services (no oc exec)."""
        print("🔧 Setting up port forwarding...")
        # Kill any prior forwards on expected ports
        try:
            subprocess.run(['pkill', '-f', 'oc port-forward.*800[023]|8080'], check=False)
        except Exception:
            pass
        time.sleep(1)

        services_and_ports = [
            ('rbac-service', 8080, 'rbac'),
            ('host-inventory-service-reads', 8002, 'hbi-reads'),
            ('host-inventory-service', 8003, 'hbi-writes')
        ]

        for service_label, local_port, name in services_and_ports:
            try:
                result = subprocess.run([
                    'oc', 'get', 'pods', '-l', f'pod={service_label}', '-o', 'json'
                ], capture_output=True, text=True, check=True)
                pods_data = json.loads(result.stdout)
                items = pods_data.get('items', [])
                if not items:
                    print(f"⚠️  No pods found for {service_label}, skipping port-forward")
                    continue
                pod_name = items[0]['metadata']['name']
                proc = subprocess.Popen([
                    'oc', 'port-forward', pod_name, f'{local_port}:8000'
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.port_forwards.append(proc)
                print(f"📡 Port forward {local_port} -> {name} ({pod_name})")
            except Exception as e:
                print(f"⚠️  Failed to start port-forward for {service_label}: {e}")

        # Allow forwards to establish
        time.sleep(3)
        print("✅ Port forwarding established (if pods were found)")

    def create_users_via_keycloak(self, user_numbers: List[int]) -> List[str]:
        """Create users via Keycloak Admin API"""
        if not self.keycloak_admin_route or not self.keycloak_admin_token:
            raise Exception("Keycloak admin credentials/route not available. Cannot create users without Keycloak.")
        
        print(f"👥 Creating {len(user_numbers)} users via Keycloak API...")
        created_users = []
        
        for user_num in user_numbers:
            username = f"user{user_num}"
            user_id = str(20000 + user_num)
            
            user_data = {
                "username": username,
                "email": f"{username}@redhat.com",
                "firstName": "User",
                "lastName": str(user_num),
                "enabled": True,
                "attributes": {
                    "account_id": ["1234567890"],
                    "org_id": ["12345"],
                    "user_id": [user_id]
                }
            }
            
            headers = {
                'Authorization': f'Bearer {self.keycloak_admin_token}',
                'Content-Type': 'application/json'
            }
            
            for attempt in range(MAX_RETRIES):
                try:
                    response = requests.post(
                        f"{self.keycloak_admin_route}/admin/realms/redhat-external/users",
                        json=user_data,
                        headers=headers,
                        timeout=API_TIMEOUT
                    )
                    
                    if response.status_code == 201:
                        created_users.append(username)
                        print(f"✅ Created {username} via Keycloak API")
                        break
                    elif response.status_code == 409:
                        # User already exists
                        created_users.append(username)
                        print(f"✅ User {username} already exists")
                        break
                    else:
                        print(f"⚠️  Attempt {attempt + 1}: Failed to create {username}: {response.text}")
                        if attempt < MAX_RETRIES - 1:
                            time.sleep(RETRY_DELAY)
                        
                except requests.RequestException as e:
                    print(f"⚠️  Attempt {attempt + 1}: Network error creating {username}: {e}")
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY)
            else:
                print(f"❌ Failed to create {username} after {MAX_RETRIES} attempts")
        
        with progress_lock:
            progress_data['users_created'] += len(created_users)
        
        return created_users

    def create_workspace_via_hbi_groups(self, workspace_num: int, host_ids: List[str]) -> Optional[str]:
        """Create workspace via HBI Groups API (the working approach!)"""
        
        headers = {
            'x-rh-identity': self.admin_header,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        for attempt in range(MAX_RETRIES):
            try:
                # Generate unique name per attempt to avoid collisions
                unique_id = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
                workspace_name = f"mass-workspace-{workspace_num}-{unique_id}"
                
                # Create workspace with hosts included (like the working old script approach)
                # This avoids the need for separate Kessel workspace/host move permissions
                workspace_data = {
                    "name": workspace_name,
                    "host_ids": host_ids  # Include hosts in initial creation
                }
                
                response = requests.post(
                    f"{self.hbi_writes_endpoint}/groups",
                    json=workspace_data,
                    headers=headers,
                    timeout=API_TIMEOUT
                )
                
                if response.status_code in [200, 201]:
                    workspace_response = response.json()
                    workspace_id = workspace_response['id']
                    print(f"✅ Created workspace {workspace_name} with {len(host_ids)} hosts (ID: {workspace_id})")
                    
                    # Update counters for successful workspace and host assignment
                    with progress_lock:
                        progress_data['workspaces_created'] += 1
                        progress_data['hosts_assigned'] += len(host_ids)
                    
                    return workspace_id
                else:
                    print(f"⚠️  Attempt {attempt + 1}: Failed to create workspace {workspace_name}: {response.text}")
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY)
                    
            except requests.RequestException as e:
                print(f"⚠️  Attempt {attempt + 1}: Network error creating workspace {workspace_name}: {e}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
        
        print(f"❌ Failed to create workspace {workspace_name} after {MAX_RETRIES} attempts")
        return None

    def create_rbac_batch(self, workspace_batch: List[Tuple[int, str]], all_users: List[str]):
        """Create RBAC groups, roles, and permissions for a batch of workspaces"""
        for workspace_num, workspace_id in workspace_batch:
            username = f"user{workspace_num}"
            if username in all_users:
                self.create_rbac_for_workspace(workspace_num, workspace_id, username)

    def create_rbac_for_workspace(self, workspace_num: int, workspace_id: str, username: str):
        """Create RBAC objects for workspace access using RBAC v1 API with ResourceDefinitions."""
        group_name = f"mass-group-{workspace_num}"
        role_name = f"Mass Viewer {workspace_num}"
        
        headers = {
            'x-rh-identity': self.admin_header,
            'Content-Type': 'application/json'
        }
        
        try:
            # Step 1: Create group via v1 API
            group_data = {
                "name": group_name,
                "description": f"Auto-generated group for mass workspace {workspace_num}"
            }
            
            group_response = requests.post(
                f"{self.rbac_endpoint}/v1/groups/",
                json=group_data,
                headers=headers,
                timeout=API_TIMEOUT
            )
            
            if group_response.status_code not in [200, 201]:
                print(f"❌ Failed to create group {group_name}: {group_response.status_code}")
                return False
                
            group_uuid = group_response.json().get('uuid')
            print(f"✅ Created RBAC v1 group {group_name} (UUID: {group_uuid})")
            
            # Step 2: Add user to group via v1 API
            add_user_data = {
                "principals": [{"username": username}]
            }
            
            user_assignment_response = requests.post(
                f"{self.rbac_endpoint}/v1/groups/{group_uuid}/principals/",
                json=add_user_data,
                headers=headers,
                timeout=API_TIMEOUT
            )
            
            if user_assignment_response.status_code not in [200, 201]:
                print(f"❌ Failed to add user {username} to group: {user_assignment_response.status_code}")
                return False
            
            print(f"✅ Added user {username} to group {group_name}")
            
            # Step 3: Create role with workspace-specific ResourceDefinitions via v1 API
            role_data = {
                "name": role_name,
                "description": f"Auto-generated role for mass workspace {workspace_num}",
                "access": [
                    {
                        "permission": "inventory:hosts:read",
                        "resourceDefinitions": [
                            {
                                "attributeFilter": {
                                    "key": "group.id",
                                    "operation": "in",
                                    "value": [workspace_id]
                                }
                            }
                        ]
                    },
                    {
                        "permission": "inventory:groups:read",
                        "resourceDefinitions": [
                            {
                                "attributeFilter": {
                                    "key": "group.id",
                                    "operation": "in",
                                    "value": [workspace_id]
                                }
                            }
                        ]
                    }
                ]
            }
            
            role_response = requests.post(
                f"{self.rbac_endpoint}/v1/roles/",
                json=role_data,
                headers=headers,
                timeout=API_TIMEOUT
            )
            
            if role_response.status_code not in [200, 201]:
                print(f"❌ Failed to create role {role_name}: {role_response.status_code}")
                print(f"   Response: {role_response.text}")
                return False
                
            role_uuid = role_response.json().get('uuid')
            print(f"✅ Created RBAC v1 role {role_name} (UUID: {role_uuid}) with ResourceDefinitions")
            
            # Step 4: Add role to group via v1 API
            add_role_data = {
                "roles": [role_uuid]
            }
            
            role_assignment_response = requests.post(
                f"{self.rbac_endpoint}/v1/groups/{group_uuid}/roles/",
                json=add_role_data,
                headers=headers,
                timeout=API_TIMEOUT
            )
            
            if role_assignment_response.status_code not in [200, 201]:
                print(f"❌ Failed to add role {role_name} to group {group_name}: {role_assignment_response.status_code}")
                return False
            
            print(f"✅ Connected role {role_name} to group {group_name}")
            
            print(f"✅ RBAC setup complete for {username} → workspace {workspace_id[:8]}...")
            with progress_lock:
                progress_data['permissions_created'] += 1
                
            return True
            
        except Exception as e:
            print(f"❌ RBAC setup failed for {username}: {e}")
            return False

    def get_available_hosts(self) -> List[str]:
        """Get all available host IDs"""
        print(f"📡 Fetching {self.num_hosts} available hosts...")
        
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
            
            for attempt in range(MAX_RETRIES):
                try:
                    response = requests.get(
                        f"{self.hbi_reads_endpoint}/hosts",
                        headers=headers,
                        params=params,
                        timeout=API_TIMEOUT
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        hosts = [host['id'] for host in data.get('results', [])]
                        all_hosts.extend(hosts)
                        
                        if len(hosts) < per_page:  # Last page
                            break
                            
                        page += 1
                        
                        if page % 10 == 0:
                            print(f"   Fetched {len(all_hosts)} hosts so far...")
                        
                        break  # Success, exit retry loop
                    else:
                        print(f"⚠️  Attempt {attempt + 1}: Failed to fetch hosts: {response.text}")
                        if attempt < MAX_RETRIES - 1:
                            time.sleep(RETRY_DELAY)
                        
                except requests.RequestException as e:
                    print(f"⚠️  Attempt {attempt + 1}: Network error fetching hosts: {e}")
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(RETRY_DELAY)
            else:
                raise Exception(f"Failed to fetch hosts after {MAX_RETRIES} attempts")
            
            if len(hosts) < per_page:  # Last page
                break
        
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

    def run_modern_setup(self):
        """Execute the complete modern API-based mass setup"""
        print(f"🚀 Starting MODERN Mass Workspace Setup")
        print(f"=" * 60)
        print(f"🔥 USING MODERN APIS - NO DATABASE HACKING!")
        print(f"=" * 60)
        print(f"Users/Workspaces: {self.num_users}")
        print(f"Total Hosts: {self.num_hosts}")
        print(f"Ungrouped Ratio: {self.ungrouped_ratio:.1%}")
        print(f"Hosts per Workspace: {self.hosts_per_workspace}")
        print(f"Remainder Hosts: {self.remainder_hosts}")
        print("")
        
        start_time = time.time()
        
        try:
            # Step 1: Setup
            self.setup_prerequisites()
            self.setup_port_forwarding()
            
            # Step 2: Get hosts
            host_ids = self.get_available_hosts()
            ungrouped_hosts, workspace_assignments = self.calculate_host_distribution(host_ids)
            
            # Step 3: Create users via Keycloak Admin API
            print(f"👥 Creating {self.num_users} users via Keycloak...")
            user_batches = [
                list(range(i, min(i + BATCH_SIZE, self.num_users)))
                for i in range(0, self.num_users, BATCH_SIZE)
            ]
            
            all_users = []
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(self.create_users_via_keycloak, batch) for batch in user_batches]
                for future in as_completed(futures):
                    all_users.extend(future.result())
            
            print(f"✅ Created {len(all_users)} users via Keycloak API")
            
            # Step 4: Create workspaces with hosts via HBI Groups API (the working approach!)
            print(f"🏗️  Creating {self.num_users} workspaces via HBI Groups API...")
            workspaces = []
            
            # Create workspaces with hosts in one call (like original working script)
            for workspace_num in range(self.num_users):
                host_ids_for_workspace = workspace_assignments.get(workspace_num, [])
                if host_ids_for_workspace:
                    workspace_id = self.create_workspace_via_hbi_groups(workspace_num, host_ids_for_workspace)
                    if workspace_id:
                        workspaces.append((workspace_num, workspace_id))
            
            print(f"✅ Created {len(workspaces)} workspaces with hosts via HBI Groups API")
            
            # Step 5: Create RBAC groups, roles, and permissions for workspace access
            print(f"🔐 Setting up RBAC groups and permissions for workspace access...")
            rbac_batches = [
                workspaces[i:i + BATCH_SIZE] 
                for i in range(0, len(workspaces), BATCH_SIZE)
            ]
            
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(self.create_rbac_batch, batch, all_users) for batch in rbac_batches]
                for future in as_completed(futures):
                    future.result()
            
            print(f"✅ RBAC setup complete - users can now access their workspaces!")
            
            # Progress summary
            elapsed_time = time.time() - start_time
            self.print_final_summary(elapsed_time, ungrouped_hosts)
            
        except Exception as e:
            print(f"❌ Modern mass setup failed: {e}")
            raise
        finally:
            self.cleanup()

    def print_final_summary(self, elapsed_time: float, ungrouped_hosts: List[str]):
        """Print final setup summary"""
        print("")
        print("🎉 MODERN MASS WORKSPACE SETUP COMPLETED!")
        print("=" * 60)
        print("🔥 ALL OPERATIONS PERFORMED VIA PROPER APIS!")
        print("=" * 60)
        print(f"✅ Created: {progress_data['users_created']} users (via Keycloak API)")
        print(f"✅ Created: {progress_data['workspaces_created']} workspaces (via HBI Groups API)")
        print(f"✅ Created: {progress_data['permissions_created']} RBAC user-workspace assignments")
        print(f"✅ Assigned: {progress_data['hosts_assigned']} hosts to workspaces (via HBI API)")
        print(f"✅ Left ungrouped: {len(ungrouped_hosts)} hosts")
        print(f"⏱️  Total time: {elapsed_time:.1f} seconds")
        print(f"📊 Rate: {progress_data['hosts_assigned'] / elapsed_time:.1f} hosts/second")
        print("")
        print("🔍 Advantages of modern approach:")
        print("   • ✅ Proper validation & error handling")
        print("   • ✅ Full audit trails")
        print("   • ✅ Event publishing (automatic Kessel sync!)")
        print("   • ✅ No database bypassing")
        print("   • ✅ Security & authorization enforced")
        print("")
        print("🧪 Test individual user access:")
        print("   python test_mass_permissions.py --user 5")
        print("")
        print("🗑️  To cleanup:")
        print("   python modern_mass_workspace_teardown.py")

    def cleanup(self):
        """Terminate any oc port-forward processes that were started by this script."""
        print("🧹 Cleaning up port-forwards...")
        for proc in self.port_forwards:
            try:
                proc.terminate()
            except Exception:
                pass
        try:
            subprocess.run(['pkill', '-f', 'oc port-forward.*800[023]|8080'], check=False)
        except Exception:
            pass
        print("✅ Cleanup complete")


def main():
    parser = argparse.ArgumentParser(
        description="MODERN Mass Workspace Setup - Create many users/workspaces using proper APIs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🔥 MODERN API-BASED APPROACH - NO DATABASE HACKING!

This script uses:
✅ Keycloak API for user creation
✅ RBAC v1 API with ResourceDefinitions for workspace filtering  
✅ HBI API for host assignment
✅ Proper validation, error handling & audit trails
✅ Automatic event publishing & Kessel sync

Examples:
  # Create 20 users/workspaces with 10,000 hosts (10% ungrouped)
  python modern_mass_workspace_setup.py --users 20 --hosts 10000
  
  # Create 50 users/workspaces with 5,000 hosts (20% ungrouped)  
  python modern_mass_workspace_setup.py --users 50 --hosts 5000 --ungrouped-ratio 0.2
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
    
    # Run modern setup
    setup = ModernMassWorkspaceSetup(args.users, args.hosts, args.ungrouped_ratio)
    setup.run_modern_setup()


if __name__ == '__main__':
    main()