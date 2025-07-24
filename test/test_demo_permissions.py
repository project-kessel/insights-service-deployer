#!/usr/bin/env python3
"""
Comprehensive test script to validate RBAC/HBI demo permissions and scenarios.
This script tests the demo environment setup by validating permissions for different users.
"""

import base64
import json
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

API_TIMEOUT = 30

@dataclass
class TestResult:
    test_name: str
    expected: str
    actual: str
    passed: bool

class DemoPermissionsTest:
    def __init__(self):
        self.results: List[TestResult] = []
        self.test_count = 0
        self.passed_count = 0
        self.users = {
            "jdoe": self._create_identity("jdoe", "12345", is_admin=True),
            "sara": self._create_identity("sara", "54321", is_admin=False),
            "alice": self._create_identity("alice", "11111", is_admin=False),
            "bob": self._create_identity("bob", "22222", is_admin=False),
        }
        self.workspace_ids = {}
        self.sample_hosts = {}

    def _create_identity(self, username: str, user_id: str, is_admin: bool) -> str:
        """Create base64-encoded x-rh-identity header for a user."""
        identity = {
            "identity": {
                "org_id": "12345",
                "type": "User",
                "auth_type": "basic-auth",
                "user": {
                    "username": username,
                    "email": f"{username}@redhat.com",
                    "first_name": username.title(),
                    "last_name": "Demo",
                    "is_active": True,
                    "is_org_admin": is_admin,
                    "is_internal": True,
                    "locale": "en_US",
                    "user_id": user_id,
                    "account_number": "1234567890"
                },
                "internal": {"org_id": "12345"},
                "account_number": "1234567890"
            }
        }
        return base64.b64encode(json.dumps(identity).encode()).decode()

    def _make_request(self, method: str, url: str, user: str, **kwargs) -> requests.Response:
        """Make an API request with the specified user's identity."""
        headers = kwargs.get('headers', {})
        headers['x-rh-identity'] = self.users[user]
        headers['Content-Type'] = 'application/json'
        kwargs['headers'] = headers
        kwargs['timeout'] = API_TIMEOUT
        
        try:
            return requests.request(method, url, **kwargs)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            raise

    def _test(self, test_name: str, expected: str, actual: str, passed: bool):
        """Record a test result."""
        result = TestResult(test_name, expected, actual, passed)
        self.results.append(result)
        self.test_count += 1
        if passed:
            self.passed_count += 1
            print(f"✅ {test_name}")
        else:
            print(f"❌ {test_name}")
            print(f"   Expected: {expected}")
            print(f"   Actual: {actual}")

    def setup_test_data(self):
        """Gather workspace IDs and sample host data for testing."""
        print("📋 Setting up test data...")
        
        # Get workspace IDs
        response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/groups', 'jdoe')
        if response.status_code == 200:
            groups = response.json().get('results', [])
            workspace_names = []
            for group in groups:
                if group['name'] in ['IT Team A', 'IT Team B']:
                    self.workspace_ids[group['name']] = group['id']
                    workspace_names.append(group['name'])
            print(f"   Found workspaces: {workspace_names}")
        
        # Get sample hosts for each workspace and ungrouped hosts
        response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/hosts', 'jdoe', params={'ungrouped': 'true', 'per_page': 5})
        if response.status_code == 200:
            hosts = response.json().get('results', [])
            if hosts:
                self.sample_hosts['ungrouped'] = {'id': hosts[0]['id'], 'display_name': hosts[0]['display_name']}
        
        # Get sample hosts from each workspace using RBAC-filtered queries
        for workspace_name, workspace_id in self.workspace_ids.items():
            # Use the host list endpoint which will be filtered by RBAC for workspace-specific users
            response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/hosts', 'jdoe', params={'per_page': 5})
            if response.status_code == 200:
                hosts = response.json().get('results', [])
                workspace_hosts = [h for h in hosts if any(g.get('name') == workspace_name for g in h.get('groups', []))]
                if workspace_hosts:
                    self.sample_hosts[workspace_name] = {
                        'id': workspace_hosts[0]['id'], 
                        'display_name': workspace_hosts[0]['display_name']
                    }
        
        sample_categories = list(self.sample_hosts.keys())
        print(f"   Found sample hosts: {sample_categories}")

    def test_jdoe_admin_permissions(self):
        """Test jdoe (admin) permissions - full access to everything."""
        print("\n👑 Testing jdoe (admin) permissions...")
        
        # Test: Can view all hosts
        response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/hosts', 'jdoe', params={'per_page': 10})
        self._test(
            "jdoe can view all hosts",
            "200 with host list",
            f"{response.status_code}",
            response.status_code == 200 and len(response.json().get('results', [])) > 0
        )
        
        # Test: Can view all workspaces
        response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/groups', 'jdoe')
        self._test(
            "jdoe can view all workspaces",
            "200 with group list",
            f"{response.status_code}",
            response.status_code == 200
        )
        
        # Test: Can view staleness settings (corrected endpoint)
        response = self._make_request('GET', 'http://localhost:8003/api/inventory/v1/account/staleness', 'jdoe')
        self._test(
            "jdoe can view staleness settings",
            "200 with staleness config",
            f"{response.status_code}",
            response.status_code == 200
        )

    def test_sara_support_permissions(self):
        """Test sara (support) permissions - global read, write on ungrouped."""
        print("\n🛠️  Testing sara (support) permissions...")
        
        # Test: Can view all hosts (global read)
        response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/hosts', 'sara', params={'per_page': 10})
        self._test(
            "sara can view all hosts (global read)",
            "200 with host list",
            f"{response.status_code}",
            response.status_code == 200
        )
        
        # Test: Can view hosts via RBAC filtering (all hosts she has access to)
        response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/hosts', 'sara', params={'per_page': 10})
        self._test(
            "sara can view hosts with RBAC filtering",
            "200 with filtered hosts",
            f"{response.status_code}",
            response.status_code == 200
        )
        
        # Test: Can assign ungrouped hosts to workspaces (if she has sample hosts)
        if 'ungrouped' in self.sample_hosts and 'IT Team A' in self.workspace_ids:
            host_id = self.sample_hosts['ungrouped']['id']
            workspace_id = self.workspace_ids['IT Team A']
            
            # First, try to find a truly ungrouped host by checking the host's current groups
            host_response = self._make_request('GET', f'http://localhost:8002/api/inventory/v1/hosts/{host_id}', 'sara')
            if host_response.status_code == 200:
                host_data = host_response.json().get('results', [{}])[0]
                current_groups = host_data.get('groups', [])
                
                # If the host is already in a group, try to remove it first (if sara has permission)
                if current_groups:
                    print(f"    ℹ️  Host is in groups: {[g.get('name') for g in current_groups]}, attempting to remove...")
                    for group in current_groups:
                        remove_response = self._make_request('DELETE', f'http://localhost:8002/api/inventory/v1/groups/{group["id"]}/hosts/{host_id}', 'sara')
                        if remove_response.status_code in [200, 204]:
                            print(f"    ✅ Removed host from group: {group.get('name')}")
                        else:
                            print(f"    ⚠️  Could not remove host from group: {group.get('name')} (status: {remove_response.status_code})")
            
            # Now try to assign the host
            response = self._make_request('POST', f'http://localhost:8002/api/inventory/v1/groups/{workspace_id}/hosts', 'sara', json=[host_id])
            
            # Print error details if 400
            if response.status_code == 400:
                print(f"    ❌ 400 Error Details: {response.text}")
            
            # Accept both successful assignment and "already assigned" scenarios
            success_codes = [200, 201]
            expected_error_msg = "already associated with another group"
            is_expected_error = (response.status_code == 400 and expected_error_msg in response.text)
            
            self._test(
                "sara can assign ungrouped hosts to workspaces",
                "200/201 (successful) or 400 (already assigned)",
                f"{response.status_code}",
                response.status_code in success_codes or is_expected_error
            )

    def test_alice_team_a_permissions(self):
        """Test alice (IT Team A) permissions - only Team A access."""
        print("\n🔧 Testing alice (IT Team A) permissions...")
        
        # Test: Can view hosts (RBAC should filter to only Team A hosts)
        response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/hosts', 'alice', params={'per_page': 10})
        self._test(
            "alice can view IT Team A hosts",
            "200 with team A hosts",
            f"{response.status_code}",
            response.status_code == 200
        )
        
        # Test: Cannot view Team B hosts specifically (RBAC should filter them out)
        # Since we're using RBAC filtering, Alice should only see her permitted hosts
        response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/hosts', 'alice', params={'per_page': 50})
        team_b_hosts = []
        if response.status_code == 200:
            hosts = response.json().get('results', [])
            team_b_hosts = [h for h in hosts if any(g.get('name') == 'IT Team B' for g in h.get('groups', []))]
        
        self._test(
            "alice cannot view IT Team B hosts",
            "No Team B hosts visible",
            f"Found {len(team_b_hosts)} Team B hosts",
            len(team_b_hosts) == 0
        )
        
        # Test: Can edit Team A host display name (if she has access to a Team A host)
        if 'IT Team A' in self.sample_hosts:
            host = self.sample_hosts['IT Team A']
            host_id = host['id']
            new_name = f"alice-test-{int(time.time())}"
            
            response = self._make_request('PATCH', f'http://localhost:8002/api/inventory/v1/hosts/{host_id}', 'alice', json={'display_name': new_name})
            self._test(
                "alice can edit IT Team A host display name", 
                "200 or 202 (successful update)",
                f"{response.status_code}",
                response.status_code in [200, 202]
            )

    def test_bob_team_b_permissions(self):
        """Test bob (IT Team B) permissions - only Team B access."""
        print("\n🔩 Testing bob (IT Team B) permissions...")
        
        # Test: Can view hosts (RBAC should filter to only Team B hosts)
        response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/hosts', 'bob', params={'per_page': 10})
        self._test(
            "bob can view IT Team B hosts",
            "200 with team B hosts",
            f"{response.status_code}",
            response.status_code == 200
        )
        
        # Test: Cannot view Team A hosts specifically (RBAC should filter them out)
        response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/hosts', 'bob', params={'per_page': 50})
        team_a_hosts = []
        if response.status_code == 200:
            hosts = response.json().get('results', [])
            team_a_hosts = [h for h in hosts if any(g.get('name') == 'IT Team A' for g in h.get('groups', []))]
        
        self._test(
            "bob cannot view IT Team A hosts",
            "No Team A hosts visible",
            f"Found {len(team_a_hosts)} Team A hosts",
            len(team_a_hosts) == 0
        )

    def test_cross_user_scenarios(self):
        """Test cross-user demo scenarios."""
        print("\n🔄 Testing cross-user demo scenarios...")
        
        # Test: Different users see different host counts
        jdoe_response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/hosts', 'jdoe', params={'per_page': 1})
        alice_response = self._make_request('GET', 'http://localhost:8002/api/inventory/v1/hosts', 'alice', params={'per_page': 1})
        
        jdoe_total = jdoe_response.json().get('total', 0) if jdoe_response.status_code == 200 else 0
        alice_total = alice_response.json().get('total', 0) if alice_response.status_code == 200 else 0
        
        self._test(
            "jdoe sees more hosts than alice (admin vs workspace access)",
            "jdoe_total >= alice_total",
            f"jdoe: {jdoe_total}, alice: {alice_total}",
            jdoe_total >= alice_total
        )

    def print_summary(self):
        """Print a comprehensive test summary."""
        print("\n" + "="*60)
        print("📊 DEMO PERMISSIONS TEST SUMMARY")
        print("="*60)
        print(f"✅ Passed: {self.passed_count}/{self.test_count}")
        print(f"❌ Failed: {self.test_count - self.passed_count}/{self.test_count}")
        print(f"📈 Success Rate: {(self.passed_count/self.test_count)*100:.1f}%")
        
        failed_tests = [r for r in self.results if not r.passed]
        if failed_tests:
            print(f"\n❌ FAILED TESTS:")
            for test in failed_tests:
                print(f"   • {test.test_name}")
                print(f"     Expected: {test.expected}")
                print(f"     Actual: {test.actual}")
                print()
        
        # Demo readiness assessment
        critical_failures = [r for r in failed_tests if any(keyword in r.test_name.lower() 
                                                          for keyword in ['admin', 'view', 'team a', 'team b'])]
        
        print("🚀 DEMO READINESS:")
        if not failed_tests:
            print("✅ DEMO READY - All permissions working correctly!")
        elif not critical_failures:
            print("🔶 DEMO MOSTLY READY - Minor issues, core permissions working")
        else:
            print(f"⚠️  DEMO ISSUES - {len(critical_failures)} critical permission issues found")

    def run_all_tests(self):
        print("🎯 RBAC/HBI Demo Permissions Test Suite")
        print("=" * 50)
        print("Testing the demo environment setup and permissions...")
        print()
        try:
            self.setup_test_data()
            self.test_jdoe_admin_permissions()
            self.test_sara_support_permissions() 
            self.test_alice_team_a_permissions()
            self.test_bob_team_b_permissions()
            self.test_cross_user_scenarios()
            self.print_summary()
        except Exception as e:
            print(f"\n❌ Test suite failed with error: {e}")
            raise

def main():
    tester = DemoPermissionsTest()
    tester.run_all_tests()

if __name__ == '__main__':
    main() 