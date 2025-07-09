# Workspace-Based RBAC Setup for Host Inventory

This directory contains scripts to set up workspace-based RBAC (Role-Based Access Control) for the Host Inventory service, allowing users to access only hosts within their assigned workspaces.

## 🎯 Overview

The workspace-based RBAC system ensures that users can only see hosts that belong to their assigned workspaces, providing proper data isolation and security. This is achieved by:

1. Creating users with limited permissions
2. Setting up workspaces with specific hosts
3. Configuring RBAC policies with ResourceDefinitions that restrict access to workspace UUIDs
4. Removing default host permissions to enforce workspace restrictions

## 📋 Prerequisites

- OpenShift cluster access with appropriate permissions
- RBAC service and Host Inventory service running
- At least 20 hosts in the system for testing

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)

Run the complete setup for both Luke and Leia:

```bash
./setup_workspace_rbac_demo.sh
```

This script will:
- Set up Luke with 4 hosts in his workspace
- Set up Leia with 2 hosts in her workspace  
- Remove default host permissions
- Test both users' access

### Option 2: Manual Setup

#### Step 1: Set up individual users

```bash
# Set up Luke (4 hosts)
./setup_luke.sh

# Set up Leia (2 hosts)
./setup_leia.sh
```

#### Step 2: Remove default permissions (CRITICAL)

```bash
# This must be done AFTER setting up users but BEFORE testing
../remove_default_host_admin.sh
```

#### Step 3: Test the setup

```bash
# Test Luke's permissions
../../test/e2e/test_luke_permissions.sh

# Test Leia's permissions  
../../test/e2e/test_leia_permissions.sh
```

## 📁 File Structure

```
scripts/hbi/users/
├── README.md                           # This documentation
├── setup_workspace_rbac_demo.sh        # Complete automated setup
├── setup_luke.sh                       # Luke setup (4 hosts)
├── setup_leia.sh                       # Leia setup (2 hosts)
├── teardown_luke.sh                    # Luke cleanup
├── teardown_leia.sh                    # Leia cleanup
├── debug_rbac.sh                       # RBAC debugging tool
├── _helpers.sh                         # Shared helper functions
└── setup_luke_demo.sh                  # Original Luke demo script

scripts/
└── remove_default_host_admin.sh        # Remove default host permissions

test/e2e/
├── test_luke_permissions.sh            # Luke permission tests
└── test_leia_permissions.sh            # Leia permission tests
```

## 🔧 Individual Scripts

### User Setup Scripts

#### `setup_luke.sh`
- Creates Luke user (ID: 12350) with limited permissions
- Creates Luke's workspace with 4 hosts
- Sets up RBAC group, role, policy, and ResourceDefinitions
- Workspace: `luke-workspace-{timestamp}`

#### `setup_leia.sh`
- Creates Leia user (ID: 12351) with limited permissions
- Creates Leia's workspace with 2 hosts
- Sets up RBAC group, role, policy, and ResourceDefinitions
- Workspace: `leia-workspace-{timestamp}`

### Cleanup Scripts

#### `teardown_luke.sh` / `teardown_leia.sh`
- Removes user, group, role, policy, and ResourceDefinitions
- Deletes workspace and host assignments
- Cleans up all RBAC configurations

### Testing Scripts

#### `test_luke_permissions.sh`
- Verifies Luke can see exactly 4 hosts
- Confirms all hosts are in Luke's workspace
- Tests workspace access permissions

#### `test_leia_permissions.sh`
- Verifies Leia can see exactly 2 hosts
- Confirms all hosts are in Leia's workspace
- Tests workspace access permissions

### Debugging Tools

#### `debug_rbac.sh`
- Analyzes RBAC configuration for Luke and Leia
- Shows group memberships, policies, and ResourceDefinitions
- Checks default access group configuration
- Helps troubleshoot permission issues

## 🎯 Expected Results

After successful setup:

### Luke's Access
- **Hosts visible**: 4 (from his workspace)
- **Workspace**: `luke-workspace-{timestamp}`
- **Permissions**: `inventory:hosts:read`, `inventory:groups:read`
- **Restrictions**: Can only see hosts in his workspace UUID

### Leia's Access
- **Hosts visible**: 2 (from her workspace)
- **Workspace**: `leia-workspace-{timestamp}`
- **Permissions**: `inventory:hosts:read`, `inventory:groups:read`
- **Restrictions**: Can only see hosts in her workspace UUID

## 🔍 How It Works

### 1. User Creation
- Users are created in RBAC with `is_org_admin: false`
- Each user gets a unique user ID and tenant assignment

### 2. Workspace Creation
- Workspaces are created with unique names and UUIDs
- Specific hosts are assigned to each workspace
- Workspace UUIDs become the group IDs for RBAC filtering

### 3. RBAC Configuration
- **Group**: User-specific group (e.g., `luke-limited-group`)
- **Role**: Limited viewer role with specific permissions
- **Policy**: Links the group to the role
- **ResourceDefinitions**: Restrict access using `group.id` filter with workspace UUID

### 4. Permission Filtering
The host inventory service uses ResourceDefinitions to filter results:
```json
{
  "key": "group.id",
  "operation": "in", 
  "value": ["workspace-uuid"]
}
```

### 5. Default Permission Removal
- Removes `inventory:hosts:*` permissions from all default roles
- Ensures users need explicit workspace permissions
- Prevents privilege escalation through default groups

## 🚨 Important Notes

### Critical Setup Order
1. ✅ Set up users and workspaces first
2. ✅ Remove default host permissions LAST
3. ✅ Test after removing default permissions

### ResourceDefinition Format
- Must be stored as a **dictionary object**, not JSON string
- Uses `attributeFilter` with `key`, `operation`, and `value` fields
- The `value` array contains workspace UUIDs

### Common Issues

#### Users see all hosts instead of workspace hosts
- **Cause**: Default host permissions not removed
- **Solution**: Run `../remove_default_host_admin.sh`

#### 500 Internal Server Error
- **Cause**: ResourceDefinition stored as JSON string instead of dict
- **Solution**: Recreate user with correct ResourceDefinition format

#### Users see no hosts
- **Cause**: Workspace UUID mismatch in ResourceDefinitions
- **Solution**: Run `debug_rbac.sh` to check configuration

## 🧪 Testing

### Automated Testing
```bash
# Test both users
./setup_workspace_rbac_demo.sh

# Test individual users
../../test/e2e/test_luke_permissions.sh
../../test/e2e/test_leia_permissions.sh
```

### Manual Testing
```bash
# Check RBAC configuration
./debug_rbac.sh

# Test API access directly
curl -H "x-rh-identity: $(echo '{"identity":{"account_number":"0000001","type":"User","user":{"username":"luke","email":"luke@example.com","first_name":"Luke","last_name":"Skywalker","is_active":true,"is_org_admin":false,"is_internal":false,"locale":"en_US","user_id":"12350"},"internal":{"org_id":"000001"}}' | base64 -w 0)" \
  "http://localhost:8002/api/inventory/v1/hosts"
```

## 🔄 Cleanup

### Remove individual users
```bash
./teardown_luke.sh
./teardown_leia.sh
```

### Restore default permissions (if needed)
```bash
# You'll need to manually add inventory:hosts:read back to default roles
# This is intentionally not automated for security reasons
```

## 📊 Architecture

```
User Request → RBAC Service → ResourceDefinition Filter → Host Inventory → Workspace Hosts
     ↓              ↓                    ↓                      ↓              ↓
   Luke         luke-limited-      group.id filter        Filtered by      Only Luke's
               group + policy      workspace UUID         workspace        4 hosts
```

## 🛠️ Troubleshooting

### Debug Commands
```bash
# Check RBAC configuration
./debug_rbac.sh

# Check service logs
oc logs -l pod=host-inventory-service-reads
oc logs -l pod=rbac-service

# Check environment variables
oc exec $(oc get pods -l pod=host-inventory-service-reads -o name | head -1) -- env | grep RBAC
```

### Common Environment Issues
- Ensure `BYPASS_RBAC=false`
- Check that RBAC service is running
- Verify port forwarding is working

## 📚 Additional Resources

- [Original Luke Demo Script](./setup_luke_demo.sh) - Reference implementation
- [Helper Functions](./_helpers.sh) - Shared utilities
- [RBAC Service Documentation](../../../docs/) - Detailed RBAC information

---

**Note**: This system provides true workspace-based isolation. Users can only access hosts within their assigned workspaces, ensuring proper data security and multi-tenancy. 