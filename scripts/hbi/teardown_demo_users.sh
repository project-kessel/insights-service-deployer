#!/usr/bin/env bash

# Teardown Demo Users - Master Script
# This script removes both Luke and Leia demo users and their RBAC components

set -e

echo "🧹 Tearing down Demo Users"
echo "=========================="
echo ""
echo "This script will:"
echo "  1. Remove Luke's user, workspace, and RBAC components"
echo "  2. Remove Leia's user, workspace, and RBAC components"
echo "  3. Clean up any remaining demo components"
echo ""
echo "⚠️  IMPORTANT: This will completely remove the demo environment!"
echo "   All demo users and workspaces will be deleted."
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
    
    # Check if required scripts exist
    local required_scripts=(
        "scripts/hbi/users/teardown_luke.sh"
        "scripts/hbi/users/teardown_leia.sh"
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

# --- Step 1: Teardown Luke ---
teardown_luke() {
    echo "🧹 Step 1: Tearing down Luke..."
    echo "==============================="
    
    if ./scripts/hbi/users/teardown_luke.sh; then
        echo "✅ Luke teardown completed successfully"
    else
        echo "⚠️  Luke teardown had issues (continuing anyway)"
    fi
    echo ""
}

# --- Step 2: Teardown Leia ---
teardown_leia() {
    echo "🧹 Step 2: Tearing down Leia..."
    echo "==============================="
    
    if ./scripts/hbi/users/teardown_leia.sh; then
        echo "✅ Leia teardown completed successfully"
    else
        echo "⚠️  Leia teardown had issues (continuing anyway)"
    fi
    echo ""
}

# --- Cleanup any remaining demo components ---
cleanup_remaining() {
    echo "🔧 Step 3: Cleaning up any remaining demo components..."
    echo "====================================================="
    
    # Kill any lingering port forwards
    pkill -f "oc port-forward.*800[23]" 2>/dev/null || true
    
    # Clean up any temporary files
    rm -f /tmp/pf_*_test.pid /tmp/pf_*_test.log 2>/dev/null || true
    rm -f /tmp/pf_*_group.pid /tmp/pf_*_group.log 2>/dev/null || true
    
    echo "✅ Cleanup completed"
    echo ""
}

# --- Print Summary ---
print_summary() {
    echo "🎉 DEMO USERS TEARDOWN COMPLETED!"
    echo "================================="
    echo ""
    echo "✅ What was removed:"
    echo "  • Luke's user, workspace, and RBAC components"
    echo "  • Leia's user, workspace, and RBAC components"
    echo "  • All demo-related temporary files"
    echo ""
    echo "📋 Current State:"
    echo "  • Demo users can no longer access the system"
    echo "  • Hosts that were in demo workspaces are now unassigned"
    echo "  • Default RBAC permissions remain as configured"
    echo "  • No host data was deleted"
    echo ""
    echo "🔄 To recreate the demo environment:"
    echo "   ./scripts/setup_demo_users.sh"
    echo ""
    echo "🎯 The demo environment has been completely removed!"
}

# --- Main Execution ---
main() {
    echo "Starting demo users teardown at $(date)"
    echo ""
    
    # Ask for confirmation
    echo "⚠️  Are you sure you want to remove the entire demo environment?"
    echo "   This will delete Luke and Leia users, their workspaces, and all RBAC components."
    echo ""
    read -p "Type 'yes' to continue: " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        echo "❌ Teardown cancelled"
        exit 1
    fi
    echo ""
    
    check_prerequisites
    
    echo "⏳ This process will take a few minutes..."
    echo "   Each step will be executed in sequence."
    echo ""
    
    teardown_luke
    teardown_leia
    cleanup_remaining
    print_summary
    
    echo ""
    echo "🏁 Demo users teardown completed at $(date)"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [--help|--force]"
        echo ""
        echo "This script removes Luke and Leia demo users and their RBAC components."
        echo "It will delete users, workspaces, groups, roles, policies, and resource definitions."
        echo ""
        echo "Options:"
        echo "  --force    Skip confirmation prompt"
        echo "  --help     Show this help message"
        echo ""
        echo "Prerequisites:"
        echo "  • OpenShift login (oc whoami)"
        echo "  • RBAC service running"
        echo ""
        echo "The script runs these steps in order:"
        echo "  1. Teardown Luke (user, workspace, RBAC)"
        echo "  2. Teardown Leia (user, workspace, RBAC)"
        echo "  3. Clean up remaining components"
        exit 0
        ;;
    --force)
        echo "Starting demo users teardown at $(date)"
        echo ""
        check_prerequisites
        echo "⏳ This process will take a few minutes..."
        echo "   Each step will be executed in sequence."
        echo ""
        teardown_luke
        teardown_leia
        cleanup_remaining
        print_summary
        echo ""
        echo "🏁 Demo users teardown completed at $(date)"
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