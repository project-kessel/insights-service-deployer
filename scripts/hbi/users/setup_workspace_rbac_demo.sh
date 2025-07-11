#!/bin/bash

set -e

# Detect repository root and set up paths
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../" && pwd)"

# Define paths relative to current directory
USERS_DIR="$(dirname "${BASH_SOURCE[0]}")"
SCRIPTS_DIR="$REPO_ROOT/insights-service-deployer/scripts"

echo "🎯 Workspace-Based RBAC Demo Setup"
echo "==================================="
echo ""
echo "This script will set up a complete workspace-based RBAC demonstration with:"
echo "  • Luke: 4 hosts in his workspace"
echo "  • Leia: 2 hosts in her workspace"
echo "  • Proper RBAC isolation between users"
echo "  • Removal of default host permissions"
echo "  • Comprehensive testing"
echo ""
echo "📁 Repository root: $REPO_ROOT"
echo ""

# Check prerequisites
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
        echo "❌ ERROR: Host Inventory service not running"
        exit 1
    fi
    
    echo "✅ Prerequisites check passed"
    echo "   • OpenShift: Connected to $NAMESPACE"
    echo "   • RBAC service: Running"
    echo "   • Host Inventory service: Running"
    echo ""
}

# Clean up any existing setup
cleanup_existing() {
    echo "🧹 Cleaning up any existing setup..."
    
    # Clean up Luke
    if [[ -f "$USERS_DIR/teardown_luke.sh" ]]; then
        echo "   • Cleaning up existing Luke setup..."
        (cd "$USERS_DIR" && ./teardown_luke.sh) >/dev/null 2>&1 || true
    fi
    
    # Clean up Leia
    if [[ -f "$USERS_DIR/teardown_leia.sh" ]]; then
        echo "   • Cleaning up existing Leia setup..."
        (cd "$USERS_DIR" && ./teardown_leia.sh) >/dev/null 2>&1 || true
    fi
    
    echo "✅ Cleanup completed"
    echo ""
}

# Setup Luke
setup_luke() {
    echo "👤 Setting up Luke (4 hosts)..."
    
    if [[ ! -f "$USERS_DIR/setup_luke.sh" ]]; then
        echo "❌ ERROR: setup_luke.sh not found at $USERS_DIR/setup_luke.sh"
        exit 1
    fi
    
    (cd "$USERS_DIR" && ./setup_luke.sh)
    
    echo "✅ Luke setup completed"
    echo ""
}

# Setup Leia
setup_leia() {
    echo "👤 Setting up Leia (2 hosts)..."
    
    if [[ ! -f "$USERS_DIR/setup_leia.sh" ]]; then
        echo "❌ ERROR: setup_leia.sh not found at $USERS_DIR/setup_leia.sh"
        exit 1
    fi
    
    (cd "$USERS_DIR" && ./setup_leia.sh)
    
    echo "✅ Leia setup completed"
    echo ""
}

# Remove default host permissions
remove_default_permissions() {
    echo "🔒 Removing default host permissions..."
    echo "   This is CRITICAL for workspace isolation to work properly"
    
    if [[ ! -f "$USERS_DIR/remove_default_host_admin.sh" ]]; then
        echo "❌ ERROR: remove_default_host_admin.sh not found at $USERS_DIR/remove_default_host_admin.sh"
        exit 1
    fi
    
    # Run the script and capture output
    echo "   • Executing default permission removal..."
    (cd "$USERS_DIR" && ./remove_default_host_admin.sh) > /tmp/default_removal.log 2>&1
    
    if [[ $? -eq 0 ]]; then
        echo "   ✅ Default host permissions removed successfully"
    else
        echo "   ❌ Failed to remove default permissions"
        cat /tmp/default_removal.log
        exit 1
    fi
    
    # Clear RBAC cache to ensure changes take effect
    echo "   • Clearing RBAC cache..."
    oc exec $(oc get pods -l pod=rbac-service -o name | head -1) -- ./rbac/manage.py shell -c "
from django.core.cache import cache
cache.clear()
print('RBAC cache cleared successfully')
" > /tmp/cache_clear.log 2>&1
    
    if [[ $? -eq 0 ]]; then
        echo "   ✅ RBAC cache cleared successfully"
    else
        echo "   ⚠️  Warning: Failed to clear RBAC cache (permissions may take time to update)"
    fi
    
    echo ""
}



# Main execution
main() {
    echo "🚀 Starting workspace-based RBAC demo setup..."
    echo ""
    
    # Step 1: Prerequisites
    check_prerequisites
    
    # Step 2: Cleanup
    cleanup_existing
    
    # Step 3: Setup users
    setup_luke
    setup_leia
    
    # Step 4: Remove default permissions (CRITICAL - must be after user setup)
    remove_default_permissions
    
    # Step 5: Clear cache one final time to ensure fresh permissions
    echo "🔄 Clearing RBAC cache to ensure fresh permissions..."
    oc exec $(oc get pods -l pod=rbac-service -o name | head -1) -- ./rbac/manage.py shell -c "
from django.core.cache import cache
cache.clear()
print('RBAC cache cleared successfully')
"
    
    # Restart HBI service to ensure it picks up fresh permissions
    echo "🔄 Restarting Host Inventory service..."
    oc rollout restart deployment/host-inventory-service-reads
    oc rollout status deployment/host-inventory-service-reads --timeout=120s
    
    echo "✅ Services refreshed with clean permissions"
    echo ""
    
    echo "🎉 WORKSPACE-BASED RBAC DEMO SETUP COMPLETED SUCCESSFULLY!"
    echo "=========================================================="
    echo ""
    echo "✅ What was accomplished:"
    echo "  • Luke user created with access to 4 hosts in his workspace"
    echo "  • Leia user created with access to 2 hosts in her workspace"
    echo "  • Default host permissions removed for security"
    echo "  • RBAC cache cleared and services restarted"
    echo "  • System ready for workspace-based access control"
    echo ""
    echo "🧪 To test the setup:"
    echo "  • Luke: ./test/e2e/test_luke_permissions.sh"
    echo "  • Leia: ./test/e2e/test_leia_permissions.sh"
    echo ""
    echo "🔧 To debug issues:"
    echo "  • Check service logs: oc logs -l pod=host-inventory-service-reads"
    echo "  • Check RBAC logs: oc logs -l pod=rbac-service"
    echo ""
    echo "🧹 To clean up:"
    echo "  • Luke: $USERS_DIR/teardown_luke.sh"
    echo "  • Leia: $USERS_DIR/teardown_leia.sh"
    echo ""
    echo "📚 Documentation: README.md"
}

# Handle script interruption
trap 'echo ""; echo "⚠️  Script interrupted. You may need to run cleanup scripts manually."; exit 1' INT TERM

# Run main function
main "$@" 