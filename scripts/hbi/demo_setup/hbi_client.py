"""
Client for interacting with the Host-Based Inventory (HBI) service.
"""

import base64
import json
import time
import requests
from typing import Dict, List

from . import config

class HBIClient:
    """A client for interacting with the HBI API."""

    def __init__(self, admin_identity: dict):
        self.admin_header = base64.b64encode(json.dumps(admin_identity).encode()).decode()

    def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make an API request with the admin identity."""
        headers = kwargs.get('headers', {})
        headers['x-rh-identity'] = self.admin_header
        headers['Content-Type'] = 'application/json'
        kwargs['headers'] = headers
        kwargs['timeout'] = config.API_TIMEOUT
        
        try:
            return requests.request(method, url, **kwargs)
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            raise

    def check_and_create_hosts(self) -> List[str]:
        """Check that we have at least REQUIRED_HOSTS hosts."""
        print("📦 Checking for at least 100 hosts...")
        
        response = self._make_request("GET", "http://localhost:8002/api/inventory/v1/hosts", 
                                      params={"ungrouped": "true", "per_page": config.REQUIRED_HOSTS})
        response.raise_for_status()
        
        ungrouped_hosts = response.json().get('results', [])
        ungrouped_host_ids = [host['id'] for host in ungrouped_hosts]
        
        if len(ungrouped_host_ids) >= config.REQUIRED_HOSTS:
            print(f"   Found {len(ungrouped_host_ids)} ungrouped hosts (sufficient for demo).")
            return ungrouped_host_ids[:config.REQUIRED_HOSTS]
        
        print(f"   Only {len(ungrouped_host_ids)} ungrouped hosts found, getting additional hosts...")
        response = self._make_request("GET", "http://localhost:8002/api/inventory/v1/hosts", 
                                      params={"per_page": config.REQUIRED_HOSTS})
        response.raise_for_status()
        
        all_hosts = response.json().get('results', [])
        all_host_ids = [host['id'] for host in all_hosts]
        
        if len(all_host_ids) < config.REQUIRED_HOSTS:
            raise Exception(f"❌ Only {len(all_host_ids)} hosts available, need {config.REQUIRED_HOSTS}")
        
        print(f"   Found {len(all_host_ids)} total hosts.")
        return all_host_ids[:config.REQUIRED_HOSTS]

    def create_workspaces(self) -> Dict[str, str]:
        """Create the workspaces via the HBI API."""
        print("🏢 Creating workspaces...")
        url = "http://localhost:8003/api/inventory/v1/groups"
        workspace_ids = {}
        
        for name in config.DEMO_WORKSPACES:
            print(f"   Processing workspace: {name}")
            payload = {"name": name}
            response = self._make_request("POST", url, json=payload)
            
            if response.status_code == 201:
                data = response.json()
                workspace_ids[name] = data['id']
                print(f"   ✅ Created workspace '{name}' with ID: {workspace_ids[name]}")
                time.sleep(1)
            elif response.status_code == 400 and "already exists" in response.text:
                print(f"   ☑️  Workspace '{name}' already exists, fetching ID...")
                search_url = "http://localhost:8002/api/inventory/v1/groups"
                search_response = self._make_request("GET", search_url, params={"name": name})
                if search_response.status_code == 200:
                    results = search_response.json().get('results', [])
                    if results:
                        workspace_ids[name] = results[0]['id']
                        print(f"   ✅ Found workspace '{name}' with ID: {results[0]['id']}")
                    else:
                        raise Exception(f"❌ Workspace '{name}' exists but could not find its ID")
            else:
                raise Exception(f"❌ Failed to create workspace '{name}': {response.status_code} {response.text}")
        return workspace_ids

    def distribute_hosts(self, all_host_ids: List[str], workspace_ids: Dict[str, str]):
        """Distribute hosts into the newly created workspaces."""
        print("🚚 Distributing hosts to workspaces...")
        
        total_to_assign = int(config.REQUIRED_HOSTS * 0.4)
        per_team_count = total_to_assign // 2
        
        team_a_hosts = all_host_ids[0:per_team_count]
        team_b_hosts = all_host_ids[per_team_count:per_team_count*2]
        
        self._assign_hosts_to_workspace("IT Team A", team_a_hosts, workspace_ids["IT Team A"])
        self._assign_hosts_to_workspace("IT Team B", team_b_hosts, workspace_ids["IT Team B"])

        print(f"✅ Host distribution completed!")

    def _assign_hosts_to_workspace(self, workspace_name: str, host_ids: List[str], workspace_id: str):
        """Assign hosts to a workspace using the correct API pattern."""
        print(f"🏷️  Assigning {len(host_ids)} hosts to {workspace_name}...")
        url = f"http://localhost:8002/api/inventory/v1/groups/{workspace_id}/hosts"
        
        response = self._make_request("POST", url, json=host_ids)
        
        if response.status_code not in [200, 201]:
            print(f"   ⚠️  Failed to assign hosts to {workspace_name}: {response.status_code}")
            print(f"      Note: {response.text}")
        else:
            print(f"   ✅ Successfully assigned {len(host_ids)} hosts to {workspace_name}")
