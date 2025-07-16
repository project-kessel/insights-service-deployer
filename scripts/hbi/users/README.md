# RBAC Multi-Tenant Demo: Alice & Bob Workspace Isolation

This demo showcases **Role-Based Access Control (RBAC)** with **workspace isolation** using Alice and Bob as example users. Each user is restricted to only see hosts within their assigned workspace, demonstrating true multi-tenant security.

## 🎯 Demo Overview

### What This Demo Shows
- **Multi-tenant RBAC**: Each user sees only their assigned hosts
- **Workspace Isolation**: Alice and Bob have separate, isolated workspaces
- **Permission Enforcement**: RBAC filtering prevents cross-workspace access
- **Dynamic Host Assignment**: Hosts are automatically assigned to user workspaces

### Demo Users
| User  | User ID | Host Count | Workspace Purpose |
|-------|---------|------------|-------------------|
| Alice | 12347   | 4 hosts    | Team-A workspace  |
| Bob   | 12348   | 2 hosts    | TeamB workspace   |

## 🚀 Quick Start

### Prerequisites
- Deployed ephemeral environment with RBAC and Host Inventory services
- OpenShift CLI (`oc`) logged in and configured
- `jq` installed for JSON processing

### 1. Run the Complete Demo
```bash
# Set up both Alice and Bob workspaces
./scripts/hbi/users/setup_alice.sh && ./scripts/hbi/users/setup_bob.sh

# Remove default permissions to enforce isolation
./scripts/hbi/remove_default_host_admin.sh

# Test both users' permissions
./test/e2e/test_alice_permissions.sh
./test/e2e/test_bob_permissions.sh
```

### 2. Expected Results
✅ **Alice**: Can see exactly **4 hosts** in her workspace  
✅ **Bob**: Can see exactly **2 hosts** in his workspace  
✅ **Isolation**: Neither user can see the other's hosts  
✅ **RBAC**: Permission filtering works correctly  

## 📋 Detailed Workflow

### Phase 1: Environment Setup
The demo assumes an ephemeral environment is already deployed with:
- 10 sample hosts created via Kafka ingestion
- Users seeded from `rbac_users_data.json` (jdoe, sara, alice, bob)
- All services running (RBAC, Host Inventory, SpiceDB)

### Phase 2: Alice Workspace Setup
```bash
./scripts/hbi/users/setup_alice.sh
```

**What it does:**
1. **Host Selection**: Selects first 4 available hosts from inventory
2. **Workspace Creation**: Creates `alice-workspace-{timestamp}` with 4 hosts
3. **RBAC Configuration**: 
   - Creates `alice-limited-group` 
   - Creates `Alice Limited Viewer` role with `inventory:hosts:read` and `inventory:groups:read`
   - Creates `alice-limited-policy` linking group and role
   - Creates ResourceDefinitions restricting access to Alice's workspace UUID

**Expected Output:**
```
✅ Alice's workspace created: 0198148a-a103-74e3-b9e7-413c73754a67
✅ 4 hosts assigned to Alice's workspace
✅ RBAC permissions configured for Alice
```

### Phase 3: Bob Workspace Setup
```bash
./scripts/hbi/users/setup_bob.sh
```

**What it does:**
1. **Host Selection**: Selects hosts 5-6 (or last 2 available) from inventory
2. **Workspace Creation**: Creates `bob-workspace-{timestamp}` with 2 hosts
3. **RBAC Configuration**: 
   - Creates `bob-limited-group`
   - Creates `Bob Limited Viewer` role with inventory permissions
   - Creates `bob-limited-policy` linking group and role
   - Creates ResourceDefinitions restricting access to Bob's workspace UUID

**Expected Output:**
```
✅ Bob's workspace created: 0198148b-0fe8-7aa2-a48d-f5151e24fa45
✅ 2 hosts assigned to Bob's workspace
✅ Bob's RBAC setup completed successfully
```

### Phase 4: Remove Default Permissions
```bash
./scripts/hbi/remove_default_host_admin.sh
```

**Critical Step**: This completely removes the `Inventory Hosts Administrator` role that gives all users default access to all hosts. Without this step, users would see ALL hosts instead of just their workspace hosts.

**What it does:**
1. Finds the `Inventory Hosts Administrator` role
2. Removes it from all policies and groups
3. Deletes all associated Access objects and ResourceDefinitions
4. Deletes the role completely

### Phase 5: Permission Testing
```bash
./test/e2e/test_alice_permissions.sh
./test/e2e/test_bob_permissions.sh
```

**Alice Test Results:**
```
📊 Alice can see 4 hosts
✅ PASS: Alice sees exactly 4 hosts (as expected)
✅ Alice can access her workspace
✅ RBAC filtering is working correctly
```

**Bob Test Results:**
```
📊 Bob can see 2 hosts  
✅ PASS: Bob sees exactly 2 hosts (as expected)
✅ Bob can access his workspace
✅ RBAC filtering is working correctly
```

## 🔧 Technical Details

### RBAC Architecture
```
User (Alice/Bob)
    ↓
Group (alice-limited-group/bob-limited-group)
    ↓  
Policy (alice-limited-policy/bob-limited-policy)
    ↓
Role (Alice Limited Viewer/Bob Limited Viewer)
    ↓
Access (inventory:hosts:read, inventory:groups:read)
    ↓
ResourceDefinition (workspace UUID restriction)
```

### Key Components

**ResourceDefinitions**: The critical component that enforces workspace isolation
```json
{
  "key": "group.id",
  "operation": "in", 
  "value": ["workspace-uuid"]
}
```

**Workspace Assignment**: Hosts are moved from "Ungrouped" to user-specific workspaces via the Groups API

**Cache Management**: RBAC cache is automatically invalidated when permissions change

### API Endpoints Used
- `GET /api/inventory/v1/hosts` - Host listing with RBAC filtering
- `GET /api/inventory/v1/groups` - Workspace listing  
- `POST /api/inventory/v1/groups` - Workspace creation with host assignment

## 🧪 Testing and Verification

### Manual Testing
```bash
# Test Alice's access
curl -H "x-rh-identity: $(echo '{"identity":{"user":{"username":"alice","user_id":"12347"},...}}' | base64 -w 0)" \
     http://localhost:8002/api/inventory/v1/hosts

# Test Bob's access  
curl -H "x-rh-identity: $(echo '{"identity":{"user":{"username":"bob","user_id":"12348"},...}}' | base64 -w 0)" \
     http://localhost:8002/api/inventory/v1/hosts
```

### Verification Points
✅ Alice sees only her 4 workspace hosts  
✅ Bob sees only his 2 workspace hosts  
✅ Neither user can see ungrouped hosts  
✅ Neither user can see the other's workspace  
✅ Host counts match workspace assignments  
✅ RBAC cache invalidation works correctly  

## 🔄 Cleanup and Reset

### Automated Teardown Scripts
The easiest way to clean up the demo is using the dedicated teardown scripts:

```bash
# Remove Alice's complete setup
./scripts/hbi/users/teardown_alice.sh

# Remove Bob's complete setup  
./scripts/hbi/users/teardown_bob.sh

# Remove both users
./scripts/hbi/users/teardown_alice.sh && ./scripts/hbi/users/teardown_bob.sh
```

**What the teardown scripts do:**
- ✅ Remove all RBAC objects (groups, policies, roles, access, resource definitions)
- ✅ Delete user workspaces and return hosts to "Ungrouped" status  
- ✅ Verify cleanup and test that users have no special permissions
- ✅ Provide detailed summary of what was removed

### Manual Cleanup (Advanced)
```bash
# Remove Alice's setup manually
oc exec $(oc get pods -l pod=rbac-service -o name) -- \
  ./rbac/manage.py shell -c "
from management.models import *
Policy.objects.filter(name='alice-limited-policy').delete()
Group.objects.filter(name='alice-limited-group').delete()  
Role.objects.filter(name='Alice Limited Viewer').delete()"

# Remove Bob's setup (similar commands)
```

### Restore Default Permissions
```bash
./scripts/hbi/add_inventory_admin_role.sh
```

### Complete Demo Reset
```bash
# Full teardown and reset sequence
./scripts/hbi/users/teardown_alice.sh && ./scripts/hbi/users/teardown_bob.sh
./scripts/hbi/add_inventory_admin_role.sh

# Verify all users can see all hosts again
./test/e2e/test_alice_permissions.sh  # Should see all hosts or get error
./test/e2e/test_bob_permissions.sh    # Should see all hosts or get error
```

## 📊 Expected Demo Flow Timeline

1. **Environment Deploy** (5-10 minutes)
2. **Alice Setup** (~30 seconds)
3. **Bob Setup** (~30 seconds)  
4. **Remove Default Permissions** (~15 seconds)
5. **Permission Tests** (~30 seconds)
6. **Total Demo Time**: ~2 minutes for workspace setup + testing

## 🔍 Troubleshooting

### Common Issues

**"User sees all hosts instead of workspace hosts"**
- Ensure `remove_default_host_admin.sh` was run
- Check that ResourceDefinitions were created correctly
- Verify RBAC cache was invalidated

**"Workspace creation failed"**
- Verify hosts exist and are accessible  
- Check port forwarding is working
- Ensure admin user (jdoe) has proper permissions

**"Permission test fails"**
- Wait 10-15 seconds for RBAC cache propagation
- Verify workspace UUIDs match in RBAC ResourceDefinitions
- Check that hosts were actually moved to workspaces

### Debug Commands
```bash
# Check Alice's RBAC setup
oc exec $(oc get pods -l pod=rbac-service -o name) -- \
  ./rbac/manage.py shell -c "
from management.models import *
alice = Principal.objects.get(username='alice')
print('Groups:', [g.name for g in Group.objects.filter(principals=alice)])
print('Policies:', [p.name for p in Policy.objects.filter(group__principals=alice)])"

# Check workspace assignments
curl -H "x-rh-identity: $JDOE_HEADER" http://localhost:8002/api/inventory/v1/groups
```

## 🎉 Success Criteria

The demo is successful when:
✅ Alice sees exactly 4 hosts  
✅ Bob sees exactly 2 hosts  
✅ No cross-workspace access occurs  
✅ RBAC filtering works correctly  
✅ Workspace isolation is enforced  

This demonstrates a **production-ready multi-tenant RBAC system** with proper workspace isolation and permission enforcement.

## 📚 Quick Reference

### Complete Demo Lifecycle
```bash
# 1. Setup both users
./scripts/hbi/users/setup_alice.sh && ./scripts/hbi/users/setup_bob.sh

# 2. Remove default permissions to enforce isolation  
./scripts/hbi/remove_default_host_admin.sh

# 3. Test permissions
./test/e2e/test_alice_permissions.sh && ./test/e2e/test_bob_permissions.sh

# 4. Teardown when done
./scripts/hbi/users/teardown_alice.sh && ./scripts/hbi/users/teardown_bob.sh

# 5. Restore default permissions (optional)
./scripts/hbi/add_inventory_admin_role.sh
```

### Individual User Management
```bash
# Alice only
./scripts/hbi/users/setup_alice.sh          # Setup
./test/e2e/test_alice_permissions.sh        # Test
./scripts/hbi/users/teardown_alice.sh       # Cleanup

# Bob only  
./scripts/hbi/users/setup_bob.sh            # Setup
./test/e2e/test_bob_permissions.sh          # Test
./scripts/hbi/users/teardown_bob.sh         # Cleanup
```

### Available Scripts
| Script | Purpose | Expected Result |
|--------|---------|-----------------|
| `setup_alice.sh` | Create Alice + 4-host workspace | Alice sees 4 hosts |
| `setup_bob.sh` | Create Bob + 2-host workspace | Bob sees 2 hosts |
| `teardown_alice.sh` | Remove Alice's setup | Alice sees 0 hosts |
| `teardown_bob.sh` | Remove Bob's setup | Bob sees 0 hosts |
| `test_alice_permissions.sh` | Test Alice's access | Reports host/workspace count |
| `test_bob_permissions.sh` | Test Bob's access | Reports host/workspace count |
| `remove_default_host_admin.sh` | Remove default permissions | Enforces workspace isolation |
| `add_inventory_admin_role.sh` | Restore default permissions | All users see all hosts | 