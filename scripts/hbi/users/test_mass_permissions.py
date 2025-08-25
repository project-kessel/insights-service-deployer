#!/usr/bin/env python3

"""
Test Mass Permissions Script
============================

This script tests permissions for individual users created by mass_workspace_setup.py

Usage:
    python test_mass_permissions.py --user 5
    python test_mass_permissions.py --user 15 --detailed
"""

import argparse
import json
import sys
import subprocess
import requests
import base64
import time

class MassPermissionTester:
    def __init__(self, user_num: int, detailed: bool = False):
        self.user_num = user_num
        self.detailed = detailed
        self.user_id = str(20000 + user_num)
        self.username = f"user{user_num}"
        
        # Debug output
        print(f"🔍 Constructor Debug: user_num={user_num}, username='{self.username}', user_id='{self.user_id}'")
        
        # User identity for API calls
        self.user_identity = {
            "identity": {
                "org_id": "12345",
                "type": "User",
                "auth_type": "basic-auth",
                "user": {
                    "username": self.username,
                    "email": f"{self.username}@redhat.com",
                    "first_name": f"User",
                    "last_name": f"{user_num}",
                    "is_active": True,
                    "is_org_admin": False,
                    "is_internal": True,
                    "locale": "en_US",
                    "user_id": self.user_id,
                    "account_number": "1234567890"
                },
                "internal": {"org_id": "12345"},
                "account_number": "1234567890"
            }
        }
        self.user_header = base64.b64encode(json.dumps(self.user_identity).encode()).decode()

    def setup_port_forwarding(self):
        """Setup port forwarding for API access"""
        print("🔧 Setting up port forwarding...")
        
        # Kill existing port forwards
        subprocess.run(['pkill', '-f', 'oc port-forward.*8002'], check=False)
        time.sleep(2)
        
        # Get HBI reads pod
        result = subprocess.run([
            'oc', 'get', 'pods', '-l', 'pod=host-inventory-service-reads', '-o', 'json'
        ], capture_output=True, text=True, check=True)
        
        pods_data = json.loads(result.stdout)
        if not pods_data['items']:
            raise Exception("❌ HBI reads pod not found")
        
        hbi_reads_pod = pods_data['items'][0]['metadata']['name']
        namespace = subprocess.run(['oc', 'project', '-q'], capture_output=True, text=True, check=True).stdout.strip()
        
        # Start port forward
        proc = subprocess.Popen([
            'oc', 'port-forward', '-n', namespace, hbi_reads_pod, '8002:8000'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Wait for port forward to be ready
        time.sleep(5)
        print("✅ Port forwarding established")
        return proc

    def test_host_access(self):
        """Test user's host access via their workspace"""
        print(f"🔍 Testing {self.username}'s host access...")
        
        headers = {
            "x-rh-identity": self.user_header,
            "Accept": "application/json"
        }
        
        # First get the user's workspace to find the workspace UUID
        workspace_response = requests.get(
            "http://localhost:8002/api/inventory/v1/groups",
            headers=headers,
            timeout=30
        )
        
        if workspace_response.status_code != 200:
            print(f"❌ Failed to get workspaces: {workspace_response.status_code}")
            return False
        
        workspace_data = workspace_response.json()
        user_workspace = None
        for workspace in workspace_data.get('results', []):
            if f"mass-workspace-{self.user_num}" in workspace['name']:
                user_workspace = workspace
                break
        
        if not user_workspace:
            print(f"❌ User's workspace not found for host testing")
            return False
        
        workspace_id = user_workspace['id']
        workspace_name = user_workspace['name']
        print(f"📋 Testing hosts in workspace: {workspace_id[:8]}...")
        
        # List hosts in this workspace via /hosts filtered by group_name
        response = requests.get(
            "http://localhost:8002/api/inventory/v1/hosts",
            headers=headers,
            params={"group_name": [workspace_name], "per_page": 100},
            timeout=30
        )
        
        if response.status_code != 200:
            print(f"❌ API Error: {response.status_code} - {response.text}")
            return False
        
        data = response.json()
        hosts = data.get('results', [])
        host_count = data.get('count', len(hosts))
        
        print(f"📊 {self.username} can see {host_count} hosts in their workspace")
        
        if self.detailed and hosts:
            print("📋 Host Details:")
            for host in hosts[:5]:  # Show first 5 hosts
                print(f"   • {host.get('id', '<unknown>')} - {host.get('display_name', 'N/A')}")
            if len(hosts) > 5:
                print(f"   ... and {len(hosts) - 5} more hosts")
        
        return host_count > 0

    def test_workspace_access(self):
        """Test user's workspace access"""
        print(f"🏗️  Testing {self.username}'s workspace access...")
        
        headers = {
            "x-rh-identity": self.user_header,
            "Accept": "application/json"
        }
        
        response = requests.get(
            "http://localhost:8002/api/inventory/v1/groups",
            headers=headers,
            timeout=30
        )
        
        if response.status_code != 200:
            print(f"❌ API Error: {response.status_code} - {response.text}")
            return False
        
        data = response.json()
        workspace_count = data.get('total', 0)
        workspaces = data.get('results', [])
        
        print(f"📊 {self.username} can see {workspace_count} workspaces")
        
        user_workspace = None
        for workspace in workspaces:
            if f"mass-workspace-{self.user_num}" in workspace['name']:
                user_workspace = workspace
                break
        
        if user_workspace:
            print(f"✅ Found user's workspace: {user_workspace['name']}")
            print(f"   • Workspace UUID: {user_workspace['id']}")
            print(f"   • Hosts in workspace: {user_workspace.get('host_count', 0)}")
            
            if self.detailed:
                print(f"   • Host IDs: {user_workspace.get('host_ids', [])}")
            
            return True
        else:
            print(f"❌ User's workspace not found")
            if self.detailed and workspaces:
                print("📋 Available workspaces:")
                for ws in workspaces:
                    print(f"   • {ws['name']} ({ws.get('host_count', 0)} hosts)")
            return False

    def test_rbac_setup(self):
        """Test user's RBAC configuration"""
        if not self.detailed:
            return True
        
        print(f"🔐 Testing {self.username}'s RBAC setup...")
        print(f"🔍 Debug: username='{self.username}', user_num={self.user_num}, user_id='{self.user_id}'")
        
        # Get RBAC pod
        result = subprocess.run([
            'oc', 'get', 'pods', '-l', 'pod=rbac-service', '-o', 'json'
        ], capture_output=True, text=True, check=True)
        
        pods_data = json.loads(result.stdout)
        if not pods_data['items']:
            print("❌ RBAC pod not found")
            return False
        
        rbac_pod = pods_data['items'][0]['metadata']['name']
        
        command = f'''./rbac/manage.py shell << 'EOFPYTHON'
from management.models import Principal, Group, Policy, Role, Access, ResourceDefinition
import json

user = None
try:
    user = Principal.objects.get(username="{self.username}")
    if user:
        print(f"✅ User found: {self.username} (ID: {{user.user_id}})")
        
        groups = Group.objects.filter(principals=user)
        print(f"📋 Groups: {{[g.name for g in groups]}}")
        
        policies = Policy.objects.filter(group__principals=user)
        print(f"📋 Policies: {{[p.name for p in policies]}}")
        
        for policy in policies:
            roles = policy.roles.all()
            print(f"📋 Roles in {{policy.name}}: {{[r.name for r in roles]}}")
            
            for role in roles:
                access_objects = Access.objects.filter(role=role)
                for access in access_objects:
                    rds = ResourceDefinition.objects.filter(access=access)
                    print(f"   • {{access.permission.permission}}: {{len(rds)}} ResourceDefinitions")
                    for rd in rds:
                        if rd.attributeFilter:
                            filter_data = rd.attributeFilter if isinstance(rd.attributeFilter, dict) else json.loads(rd.attributeFilter)
                            print(f"     - Workspace restriction: {{filter_data.get('value', [])}}")
    else:
        print(f"❌ User {self.username} not found in RBAC")

except Principal.DoesNotExist:
    print(f"❌ User {self.username} not found in RBAC")
except Exception as e:
    print(f"❌ Error: {{e}}")

exit()
EOFPYTHON'''
        
        result = subprocess.run([
            'oc', 'exec', rbac_pod, '--', 'bash', '-c', command
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(result.stdout)
            return True
        else:
            print(f"❌ RBAC query failed: {result.stderr}")
            return False

    def run_test(self):
        """Run complete permission test"""
        print(f"🧪 Testing Permissions for {self.username}")
        print("=" * 50)
        print(f"User ID: {self.user_id}")
        print(f"Expected workspace: mass-workspace-{self.user_num}-*")
        print("")
        
        port_forward_proc = None
        try:
            port_forward_proc = self.setup_port_forwarding()
            
            # Run tests
            host_test = self.test_host_access()
            workspace_test = self.test_workspace_access()
            rbac_test = self.test_rbac_setup()
            
            # Summary
            print("")
            print("=== TEST SUMMARY ===")
            if host_test:
                print("✅ Host Access: PASS")
            else:
                print("❌ Host Access: FAIL")
            
            if workspace_test:
                print("✅ Workspace Access: PASS")
            else:
                print("❌ Workspace Access: FAIL")
            
            if rbac_test:
                print("✅ RBAC Configuration: PASS")
            else:
                print("❌ RBAC Configuration: FAIL")
            
            if host_test and workspace_test and rbac_test:
                print("")
                print(f"🎉 {self.username} permissions test PASSED!")
                return True
            else:
                print("")
                print(f"❌ {self.username} permissions test FAILED!")
                return False
        
        except Exception as e:
            print(f"❌ Test failed: {e}")
            return False
        finally:
            if port_forward_proc:
                port_forward_proc.terminate()
            subprocess.run(['pkill', '-f', 'oc port-forward.*8002'], check=False)


def main():
    parser = argparse.ArgumentParser(
        description="Test Mass User Permissions - Verify individual user access",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test user5's permissions
  python test_mass_permissions.py --user 5
  
  # Test user15's permissions with detailed RBAC info
  python test_mass_permissions.py --user 15 --detailed
        """
    )
    
    parser.add_argument(
        '--user',
        type=int,
        required=True,
        help='User number to test (e.g., 5 for user5)'
    )
    
    parser.add_argument(
        '--detailed',
        action='store_true',
        help='Show detailed RBAC configuration'
    )
    
    args = parser.parse_args()
    
    if args.user < 0:
        print("❌ ERROR: User number must be non-negative")
        sys.exit(1)
    
    tester = MassPermissionTester(args.user, args.detailed)
    success = tester.run_test()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main() 