"""
Main orchestrator for setting up the RBAC Demo Scenario.
"""

import json
import subprocess
import time
from typing import List

from . import config
from .hbi_client import HBIClient
from .rbac_client import RBACClient

class DemoOrchestrator:
    """Orchestrates the setup of the RBAC demo environment."""

    def __init__(self):
        self.namespace: str = ""
        self.rbac_pod: str = ""
        self.port_forwards: List[subprocess.Popen] = []

    def _run_command(self, command: List[str], check=True, capture_output=True, text=True) -> subprocess.CompletedProcess:
        """Helper to run shell commands."""
        print(f"🔩 Running: {' '.join(command)}")
        return subprocess.run(command, check=check, capture_output=capture_output, text=text)

    def setup_prerequisites(self):
        """Check prerequisites and setup connections."""
        print("🔍 Checking prerequisites...")
        self._run_command(['oc', 'whoami'])
        
        result = self._run_command(['oc', 'project', '-q'])
        self.namespace = result.stdout.strip()
        if not self.namespace:
            raise Exception("❌ No OpenShift namespace selected. Use 'oc project <namespace>'")
        print(f"✅ Using namespace: {self.namespace}")

        self._check_service_running('rbac-service')
        self._check_service_running('host-inventory-service')

        result = self._run_command(['oc', 'get', 'pods', '-l', 'pod=rbac-service', '-o', 'json'])
        pods_data = json.loads(result.stdout)
        running_pods = [p for p in pods_data['items'] if p['status']['phase'] == 'Running' and not p['metadata'].get('deletionTimestamp')]
        if not running_pods:
            raise Exception("❌ No running RBAC service pods found")
        self.rbac_pod = running_pods[0]['metadata']['name']
        print(f"✅ Using RBAC pod: {self.rbac_pod}")

    def _check_service_running(self, service: str):
        """Check if a service has running pods."""
        print(f"   Checking for service: {service}...")
        result = self._run_command(['oc', 'get', 'pods', '-l', f'pod={service}', '--no-headers'])
        if 'Running' not in result.stdout:
            raise Exception(f"❌ Service '{service}' does not have running pods.")
        print(f"   ✅ Service '{service}' is running.")

    def setup_port_forwarding(self):
        """Setup port forwarding for API access."""
        print("🔧 Setting up port forwarding for HBI services...")
        self._run_command(['pkill', '-f', 'oc port-forward.*800[23]'], check=False)
        time.sleep(2)

        pods = {
            'reads': self._get_pod_name('host-inventory-service-reads'),
            'writes': self._get_pod_name('host-inventory-service'),
        }
        
        for port, pod_type in [(8002, 'reads'), (8003, 'writes')]:
            pod_name = pods[pod_type]
            proc = subprocess.Popen(
                ['oc', 'port-forward', '-n', self.namespace, pod_name, f'{port}:8000'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.port_forwards.append(proc)
            print(f"📡 Port forward {port} -> {pod_type} ({pod_name}) established.")

        print("⏳ Waiting for port forwards to be ready...")
        # Add verification logic here if needed

    def _get_pod_name(self, service_label: str) -> str:
        """Get a running pod name by its label."""
        result = self._run_command(['oc', 'get', 'pods', '-l', f'pod={service_label}', '-o', 'json'])
        pods_data = json.loads(result.stdout)
        running_pods = [p for p in pods_data['items'] if p['status']['phase'] == 'Running' and not p['metadata'].get('deletionTimestamp')]
        if not running_pods:
            raise Exception(f"❌ No running pods found for label: {service_label}")
        return running_pods[0]['metadata']['name']

    def run(self):
        """Execute the complete demo setup."""
        start_time = time.time()
        try:
            self.setup_prerequisites()
            self.setup_port_forwarding()

            admin_identity = {
                "identity": {
                    "org_id": "12345", "type": "User", "auth_type": "basic-auth",
                    "user": {
                        "username": "jdoe", "email": "jdoe@redhat.com", "first_name": "John",
                        "last_name": "Doe", "is_active": True, "is_org_admin": True,
                        "is_internal": True, "locale": "en_US", "user_id": "12345",
                        "account_number": "1234567890"
                    },
                    "internal": {"org_id": "12345"}, "account_number": "1234567890"
                }
            }
            
            hbi_client = HBIClient(admin_identity)
            rbac_client = RBACClient(self.namespace, self.rbac_pod)

            rbac_client.setup_rbac_users_and_principals()
            rbac_client.create_rbac_structure()
            rbac_client.create_admin_permissions()
            
            all_host_ids = hbi_client.check_and_create_hosts()
            workspace_ids = hbi_client.create_workspaces()
            hbi_client.distribute_hosts(all_host_ids, workspace_ids)
            
            rbac_client.connect_workspaces_to_rbac(workspace_ids)

            print(f"🎉 Demo setup completed in {time.time() - start_time:.2f} seconds.")

        except Exception as e:
            print(f"❌ SETUP FAILED: {e}")
        finally:
            self.cleanup()

    def cleanup(self):
        """Cleanup port forwards."""
        print("🧹 Cleaning up port forwarding processes...")
        for proc in self.port_forwards:
            proc.terminate()
        self._run_command(['pkill', '-f', 'oc port-forward.*800[23]'], check=False)
        print("✨ Cleanup complete.")

if __name__ == '__main__':
    orchestrator = DemoOrchestrator()
    orchestrator.run()
