#!/bin/bash

set -e

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
    if [[ -f "./teardown_luke.sh" ]]; then
        echo "   • Cleaning up existing Luke setup..."
        ./teardown_luke.sh >/dev/null 2>&1 || true
    fi
    
    # Clean up Leia
    if [[ -f "./teardown_leia.sh" ]]; then
        echo "   • Cleaning up existing Leia setup..."
        ./teardown_leia.sh >/dev/null 2>&1 || true
    fi
    
    echo "✅ Cleanup completed"
    echo ""
}

# Setup Luke
setup_luke() {
    echo "👤 Setting up Luke (4 hosts)..."
    
    if [[ ! -f "./setup_luke.sh" ]]; then
        echo "❌ ERROR: setup_luke.sh not found"
        exit 1
    fi
    
    ./setup_luke.sh
    
    echo "✅ Luke setup completed"
    echo ""
}

# Setup Leia
setup_leia() {
    echo "👤 Setting up Leia (2 hosts)..."
    
    if [[ ! -f "./setup_leia.sh" ]]; then
        echo "❌ ERROR: setup_leia.sh not found"
        exit 1
    fi
    
    ./setup_leia.sh
    
    echo "✅ Leia setup completed"
    echo ""
}

# Remove default host permissions
remove_default_permissions() {
    echo "🔒 Removing default host permissions..."
    echo "   This is CRITICAL for workspace isolation to work properly"
    
    if [[ ! -f "../../remove_default_host_admin.sh" ]]; then
        echo "❌ ERROR: remove_default_host_admin.sh not found"
        exit 1
    fi
    
    # Run the script and capture output
    echo "   • Executing default permission removal..."
    ../../remove_default_host_admin.sh > /tmp/default_removal.log 2>&1
    
    if [[ $? -eq 0 ]]; then
        echo "   ✅ Default host permissions removed successfully"
    else
        echo "   ❌ Failed to remove default permissions"
        cat /tmp/default_removal.log
        exit 1
    fi
    
    # Clear RBAC cache to ensure changes take effect
    echo "   • Clearing RBAC cache..."
    oc exec $(oc get pods -l pod=rbac-service -o name | head -1) -- bash -c "./rbac/manage.py shell << 'EOF'
from django.core.cache import cache
try:
    cache.clear()
    print('RBAC cache cleared successfully')
except Exception as e:
    print(f'Error clearing cache: {e}')
exit()
EOF" > /tmp/cache_clear.log 2>&1
    
    if [[ $? -eq 0 ]]; then
        echo "   ✅ RBAC cache cleared successfully"
    else
        echo "   ⚠️  Warning: Failed to clear RBAC cache (permissions may take time to update)"
    fi
    
    echo ""
}

# Test Luke's permissions
test_luke() {
    echo "🧪 Testing Luke's permissions..."
    
    if [[ ! -f "../../test/e2e/test_luke_permissions.sh" ]]; then
        echo "❌ ERROR: test_luke_permissions.sh not found"
        exit 1
    fi
    
    # Run Luke's test
    if ../../test/e2e/test_luke_permissions.sh > /tmp/luke_test.log 2>&1; then
        # Extract key results
        hosts_count=$(grep "Luke can see" /tmp/luke_test.log | grep -o "[0-9]\+ hosts" | grep -o "[0-9]\+")
        if [[ "$hosts_count" == "4" ]]; then
            echo "✅ Luke test PASSED: Can see exactly 4 hosts"
        else
            echo "❌ Luke test FAILED: Expected 4 hosts, got $hosts_count"
            return 1
        fi
    else
        echo "❌ Luke test FAILED: Check /tmp/luke_test.log for details"
        return 1
    fi
}

# Test Leia's permissions
test_leia() {
    echo "🧪 Testing Leia's permissions..."
    
    if [[ ! -f "../../test/e2e/test_leia_permissions.sh" ]]; then
        echo "❌ ERROR: test_leia_permissions.sh not found"
        exit 1
    fi
    
    # Run Leia's test
    if ../../test/e2e/test_leia_permissions.sh > /tmp/leia_test.log 2>&1; then
        # Extract key results
        hosts_count=$(grep "Leia can see" /tmp/leia_test.log | grep -o "[0-9]\+ hosts" | grep -o "[0-9]\+")
        if [[ "$hosts_count" == "2" ]]; then
            echo "✅ Leia test PASSED: Can see exactly 2 hosts"
        else
            echo "❌ Leia test FAILED: Expected 2 hosts, got $hosts_count"
            return 1
        fi
    else
        echo "❌ Leia test FAILED: Check /tmp/leia_test.log for details"
        return 1
    fi
}

# Debug RBAC configuration
debug_rbac() {
    echo "🔍 Debugging RBAC configuration..."
    
    if [[ -f "./debug_rbac.sh" ]]; then
        ./debug_rbac.sh > /tmp/rbac_debug.log 2>&1
        echo "✅ RBAC debug completed (saved to /tmp/rbac_debug.log)"
    else
        echo "⚠️  debug_rbac.sh not found, skipping debug"
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
    
    # Step 5: Debug RBAC (optional)
    debug_rbac
    
    # Step 6: Test permissions
    echo "🧪 Testing workspace-based permissions..."
    echo ""
    
    test_luke_result=0
    test_leia_result=0
    
    test_luke || test_luke_result=$?
    test_leia || test_leia_result=$?
    
    echo ""
    echo "📊 Test Results Summary"
    echo "======================"
    
    if [[ $test_luke_result -eq 0 ]]; then
        echo "✅ Luke: Can see exactly 4 hosts in his workspace"
    else
        echo "❌ Luke: Test failed (see /tmp/luke_test.log)"
    fi
    
    if [[ $test_leia_result -eq 0 ]]; then
        echo "✅ Leia: Can see exactly 2 hosts in her workspace"
    else
        echo "❌ Leia: Test failed (see /tmp/leia_test.log)"
    fi
    
    echo ""
    
    if [[ $test_luke_result -eq 0 && $test_leia_result -eq 0 ]]; then
        echo "🎉 WORKSPACE-BASED RBAC DEMO SETUP COMPLETED SUCCESSFULLY!"
        echo "=========================================================="
        echo ""
        echo "✅ What was accomplished:"
        echo "  • Luke user created with access to 4 hosts in his workspace"
        echo "  • Leia user created with access to 2 hosts in her workspace"
        echo "  • Default host permissions removed for security"
        echo "  • RBAC isolation working correctly"
        echo "  • Both users can only see their assigned workspace hosts"
        echo ""
        echo "🧪 To test again later:"
        echo "  • Luke: ../../test/e2e/test_luke_permissions.sh"
        echo "  • Leia: ../../test/e2e/test_leia_permissions.sh"
        echo ""
        echo "🔧 To debug issues:"
        echo "  • Run: ./debug_rbac.sh"
        echo "  • Check logs: /tmp/luke_test.log, /tmp/leia_test.log"
        echo ""
        echo "🧹 To clean up:"
        echo "  • Luke: ./teardown_luke.sh"
        echo "  • Leia: ./teardown_leia.sh"
        echo ""
        echo "📚 Documentation: README.md"
        
        return 0
    else
        echo "❌ WORKSPACE-BASED RBAC DEMO SETUP FAILED!"
        echo "=========================================="
        echo ""
        echo "🔍 Troubleshooting:"
        echo "  • Check test logs: /tmp/luke_test.log, /tmp/leia_test.log"
        echo "  • Run debug script: ./debug_rbac.sh"
        echo "  • Check service logs: oc logs -l pod=host-inventory-service-reads"
        echo "  • Verify RBAC service: oc logs -l pod=rbac-service"
        echo ""
        echo "🧹 To clean up and retry:"
        echo "  • ./teardown_luke.sh && ./teardown_leia.sh"
        echo "  • Then run this script again"
        
        return 1
    fi
}

# Handle script interruption
trap 'echo ""; echo "⚠️  Script interrupted. You may need to run cleanup scripts manually."; exit 1' INT TERM

# Run main function
main "$@" 