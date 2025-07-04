#!/usr/bin/env bash

# Setup Demo Users - Master Script
# This script sets up Luke and Leia demo users with proper RBAC restrictions
# and removes default host permissions to ensure proper workspace isolation

set -e

echo "🎯 Setting up Demo Users - Complete Setup"
echo "=========================================="
echo ""
echo "This script will:"
echo "  1. Setup Luke demo user with 4 hosts in his workspace"
echo "  2. Create Luke's RBAC group with workspace restrictions"
echo "  3. Setup Leia demo user with 2 hosts in her workspace"
echo "  4. Create Leia's RBAC group with workspace restrictions"
echo "  5. Remove default host permissions to ensure isolation"
echo ""
echo "⚠️  IMPORTANT: This will set up a complete demo environment with"
echo "   workspace-based access control. Default users will lose host access!"
echo ""

# --- Prerequisites ---
check_prerequisites() {
    echo "🔍 Checking prerequisites..."
    
    if ! oc whoami >/dev/null 2>&1; then
        echo "❌ ERROR: Not logged into OpenShift"
        exit 1
    fi
    
    NAMESPACE=$(oc project -q 2>/dev/null || echo "")
    if [[ -z "$NAMESPACE" ]]; then
        echo "❌ ERROR: No OpenShift namespace selected"
        exit 1
    fi
    
    if ! oc get pods -l pod=rbac-service --no-headers 2>/dev/null | grep -q Running; then
        echo "❌ ERROR: RBAC service not running"
        exit 1
    fi
    
    if ! oc get pods -l pod=host-inventory-service-reads --no-headers 2>/dev/null | grep -q Running; then
        echo "❌ ERROR: Host inventory service not running"
        exit 1
    fi
    
    # Check if required scripts exist
    local required_scripts=(
        "scripts/hbi/users/setup_luke_demo.sh"
        "scripts/hbi/users/create_luke_group.sh"
        "scripts/hbi/users/setup_leia_demo.sh"
        "scripts/hbi/users/create_leia_group.sh"
        "scripts/remove_default_host_admin.sh"
    )
    
    for script in "${required_scripts[@]}"; do
        if [[ ! -f "$script" ]]; then
            echo "❌ ERROR: Required script not found: $script"
            exit 1
        fi
        if [[ ! -x "$script" ]]; then
            echo "🔧 Making $script executable..."
            chmod +x "$script"
        fi
    done
    
    echo "✅ Prerequisites check passed"
    echo "   Namespace: $NAMESPACE"
    echo "   All required scripts found and executable"
    echo ""
}

# --- Step 1: Setup Luke Demo ---
setup_luke_demo() {
    echo "🚀 Step 1: Setting up Luke demo user..."
    echo "======================================"
    
    if ./scripts/hbi/users/setup_luke_demo.sh; then
        echo "✅ Luke demo setup completed successfully"
    else
        echo "❌ ERROR: Luke demo setup failed"
        exit 1
    fi
    echo ""
}

# --- Step 2: Create Luke Group ---
create_luke_group() {
    echo "🔐 Step 2: Creating Luke's RBAC group..."
    echo "======================================="
    
    if ./scripts/hbi/users/create_luke_group.sh; then
        echo "✅ Luke's RBAC group created successfully"
    else
        echo "❌ ERROR: Luke's RBAC group creation failed"
        exit 1
    fi
    echo ""
}

# --- Step 3: Setup Leia Demo ---
setup_leia_demo() {
    echo "🚀 Step 3: Setting up Leia demo user..."
    echo "======================================"
    
    if ./scripts/hbi/users/setup_leia_demo.sh; then
        echo "✅ Leia demo setup completed successfully"
    else
        echo "❌ ERROR: Leia demo setup failed"
        exit 1
    fi
    echo ""
}

# --- Step 4: Create Leia Group ---
create_leia_group() {
    echo "🔐 Step 4: Creating Leia's RBAC group..."
    echo "======================================="
    
    if ./scripts/hbi/users/create_leia_group.sh; then
        echo "✅ Leia's RBAC group created successfully"
    else
        echo "❌ ERROR: Leia's RBAC group creation failed"
        exit 1
    fi
    echo ""
}

# --- Step 5: Remove Default Host Permissions ---
remove_default_permissions() {
    echo "🔒 Step 5: Removing default host permissions..."
    echo "=============================================="
    echo ""
    echo "This will ensure that only Luke and Leia (with workspace-specific"
    echo "permissions) can access hosts. Default users will lose host access."
    echo ""
    
    if ./scripts/remove_default_host_admin.sh; then
        echo "✅ Default host permissions removed successfully"
    else
        echo "❌ ERROR: Failed to remove default host permissions"
        exit 1
    fi
    echo ""
}

# --- Verification ---
verify_setup() {
    echo "🧪 Verification: Testing user access..."
    echo "======================================"
    
    # Test if the e2e test scripts exist
    if [[ -f "test/e2e/test_luke_permissions.sh" ]]; then
        echo "🔍 Testing Luke's permissions..."
        if ./test/e2e/test_luke_permissions.sh; then
            echo "✅ Luke's permissions test passed"
        else
            echo "⚠️  Luke's permissions test failed (check manually)"
        fi
    else
        echo "ℹ️  Luke permissions test script not found, skipping"
    fi
    
    if [[ -f "test/e2e/test_leia_permissions.sh" ]]; then
        echo "🔍 Testing Leia's permissions..."
        if ./test/e2e/test_leia_permissions.sh; then
            echo "✅ Leia's permissions test passed"
        else
            echo "⚠️  Leia's permissions test failed (check manually)"
        fi
    else
        echo "ℹ️  Leia permissions test script not found, skipping"
    fi
    
    echo ""
}

# --- Print Summary ---
print_summary() {
    echo "🎉 DEMO USERS SETUP COMPLETED!"
    echo "=============================="
    echo ""
    echo "✅ What was created:"
    echo "  • Luke user with 4 hosts in his workspace"
    echo "  • Luke's RBAC group with workspace restrictions"
    echo "  • Leia user with 2 hosts in her workspace"
    echo "  • Leia's RBAC group with workspace restrictions"
    echo "  • Removed default host permissions for security"
    echo ""
    echo "📋 Demo Users Summary:"
    echo "  • Luke (user_id: 12350): Can see 4 hosts in luke-workspace-*"
    echo "  • Leia (user_id: 12351): Can see 2 hosts in leia-workspace-*"
    echo "  • Default users: No longer have host access (workspace isolation)"
    echo ""
    echo "🧪 Manual Testing:"
    echo "  • Test Luke: ./test/e2e/test_luke_permissions.sh"
    echo "  • Test Leia: ./test/e2e/test_leia_permissions.sh"
    echo ""
    echo "🔄 To teardown:"
    echo "  • Remove Luke: ./scripts/hbi/users/teardown_luke.sh"
    echo "  • Remove Leia: ./scripts/hbi/users/teardown_leia.sh"
    echo ""
    echo "🎯 The workspace-based permission system is now active!"
    echo "   Users can only see hosts in their assigned workspaces."
}

# --- Cleanup function ---
cleanup() {
    # Kill any lingering port forwards
    pkill -f "oc port-forward.*800[23]" 2>/dev/null || true
}
trap cleanup EXIT

# --- Main Execution ---
main() {
    echo "Starting demo users setup at $(date)"
    echo ""
    
    check_prerequisites
    
    echo "⏳ This process will take several minutes..."
    echo "   Each step will be executed in sequence with proper error handling."
    echo ""
    
    setup_luke_demo
    create_luke_group
    setup_leia_demo
    create_leia_group
    remove_default_permissions
    verify_setup
    print_summary
    
    echo ""
    echo "🏁 Demo users setup completed at $(date)"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [--help]"
        echo ""
        echo "This script sets up Luke and Leia demo users with workspace-based access control."
        echo "It will create users, workspaces, RBAC groups, and remove default permissions."
        echo ""
        echo "Prerequisites:"
        echo "  • OpenShift login (oc whoami)"
        echo "  • RBAC and Host Inventory services running"
        echo "  • Sufficient hosts in the inventory (script will add more if needed)"
        echo ""
        echo "The script runs these steps in order:"
        echo "  1. Setup Luke demo (4 hosts)"
        echo "  2. Create Luke's RBAC group"
        echo "  3. Setup Leia demo (2 hosts)"
        echo "  4. Create Leia's RBAC group"
        echo "  5. Remove default host permissions"
        exit 0
        ;;
    "")
        main "$@"
        ;;
    *)
        echo "❌ ERROR: Unknown argument: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac 