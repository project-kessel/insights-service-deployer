#!/bin/bash

# Okteto Development Environment Wrapper
set -e

# Configuration - can be overridden by environment variables
CLOWDAPP_NAME="${CLOWDAPP_NAME:-host-inventory}"
DAEMON_LOG_DIR="./okteto-logs"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[okteto-dev]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[okteto-dev]${NC} $1" >&2; }
error() { echo -e "${RED}[okteto-dev]${NC} $1" >&2; }

# Function to extract services from okteto.template.yaml
get_default_services() {
    if [[ ! -f "okteto/okteto.template.yaml" ]]; then
        error "okteto.template.yaml not found in okteto/ directory"
        error "This file is required to determine available services"
        exit 1
    fi
    
    # Extract service names from the dev: section
    # Use awk to extract everything from 'dev:' until the next top-level YAML key
    awk '
        /^dev:/ { in_dev=1; next }
        /^[a-zA-Z].*:/ { in_dev=0 }
        in_dev && /^  [a-zA-Z]/ && !/^  #/ { 
            gsub(/^  /, ""); 
            gsub(/:.*/, ""); 
            print 
        }
    ' okteto/okteto.template.yaml
}

# Load default services dynamically (compatible with older bash)
DEFAULT_SERVICES=()
while IFS= read -r service; do
    [[ -n "$service" ]] && DEFAULT_SERVICES+=("$service")
done < <(get_default_services)

# ClowdApp management functions
check_clowdapp_status() {
    local status
    status=$(oc get ClowdApp "$CLOWDAPP_NAME" -o jsonpath='{.spec.disabled}' 2>/dev/null)
    echo "${status:-false}"
}

disable_clowdapp() {
    log "Disabling ClowdApp reconciliation to allow Okteto deployment scaling..."
    if oc patch ClowdApp "$CLOWDAPP_NAME" --type=merge -p '{"spec":{"disabled": true}}' >/dev/null 2>&1; then
        log "✅ ClowdApp reconciliation disabled"
        return 0
    else
        warn "⚠️  Failed to disable ClowdApp - continuing anyway"
        return 1
    fi
}

enable_clowdapp() {
    log "Re-enabling ClowdApp reconciliation..."
    if oc patch ClowdApp "$CLOWDAPP_NAME" --type=merge -p '{"spec":{"disabled": false}}' >/dev/null 2>&1; then
        log "✅ ClowdApp reconciliation re-enabled"
        return 0
    else
        warn "⚠️  Failed to re-enable ClowdApp - you may need to manually run:"
        warn "    oc patch ClowdApp $CLOWDAPP_NAME --type=merge -p '{\"spec\":{\"disabled\": false}}'"
        return 1
    fi
}

# Check if development containers are active
check_dev_status() {
    local services=("${@:-${DEFAULT_SERVICES[@]}}")
    local active=() inactive=()
    
    for service in "${services[@]}"; do
        if oc get deployment "$service" >/dev/null 2>&1 && oc get deployment "${service}-okteto" >/dev/null 2>&1; then
            active+=("$service")
        elif oc get deployment "$service" >/dev/null 2>&1; then
            inactive+=("$service")
        fi
    done
    
    echo "${active[@]}|${inactive[@]}"
}

# Show development status
show_status() {
    local services=("${@:-${DEFAULT_SERVICES[@]}}")
    log "Current development status:"
    log "Repo path: ${INSIGHTS_HOST_INVENTORY_REPO_PATH:-"<NOT SET>"}"
    
    # Show ClowdApp status
    local clowdapp_disabled=$(check_clowdapp_status)
    if [[ "$clowdapp_disabled" == "true" ]]; then
        log "ClowdApp: 🔒 disabled (development mode)"
    else
        log "ClowdApp: 🔄 enabled (deployed mode)"
    fi
    
    local active_count=0 total_count=0
    for service in "${services[@]}"; do
        if ! oc get deployment "$service" >/dev/null 2>&1; then
            echo "  ❌ $service (not found)" >&2
            continue
        fi
        total_count=$((total_count + 1))
        local deployment_status=$(oc get deployment "${service}-okteto" --no-headers 2>/dev/null | awk '{print $2}' || echo "")
        if [[ -n "$deployment_status" ]]; then
            # Parse ready/desired replicas (e.g., "1/1" or "0/1")
            local ready=$(echo "$deployment_status" | cut -d'/' -f1)
            local desired=$(echo "$deployment_status" | cut -d'/' -f2)
            local status_indicator=""
            
            if [[ "$ready" == "$desired" && "$ready" != "0" ]]; then
                status_indicator="✅"
            else
                status_indicator="⏳"
            fi
            
            if is_daemon_mode "$service"; then
                echo "  🚀 $service (development - daemon mode) $status_indicator" >&2
            else
                echo "  🚀 $service (development) $status_indicator" >&2
            fi
            active_count=$((active_count + 1))
        else
            echo "  📦 $service (deployed)" >&2
        fi
    done
    
    echo "" >&2
    if [[ $active_count -eq 0 ]]; then
        echo "  All services in deployed mode" >&2
    elif [[ $active_count -eq $total_count ]]; then
        echo "  All services in development mode" >&2
    else
        echo "  Mixed mode ($active_count/$total_count in development)" >&2
    fi
}

# Daemon mode management functions
get_daemon_log_file() {
    local service="$1"
    local namespace=$(oc project -q 2>/dev/null || echo "unknown")
    echo "${DAEMON_LOG_DIR}/${namespace}-${service}.log"
}

is_daemon_mode() {
    local service="$1"
    local log_file=$(get_daemon_log_file "$service")
    [[ -f "$log_file" ]]
}

cleanup_daemon_files() {
    local service="$1"
    local log_file=$(get_daemon_log_file "$service")
    rm -f "$log_file"
}

cleanup_all_daemon_artifacts() {
    # Clean up all local daemon artifacts (log files only)
    if [[ -d "$DAEMON_LOG_DIR" ]]; then
        log "Cleaning up daemon log files..."
        rm -f "$DAEMON_LOG_DIR"/*.log
        # Remove directory if empty
        rmdir "$DAEMON_LOG_DIR" 2>/dev/null || true
    fi
}

wait_for_rollout() {
    local service="$1"
    log "Waiting for $service rollout to complete..."
    
    # Wait for the okteto deployment to be created first
    local timeout=60
    local count=0
    while ! oc get deployment "${service}-okteto" >/dev/null 2>&1; do
        if [[ $count -ge $timeout ]]; then
            error "Timeout waiting for ${service}-okteto deployment to be created"
            return 1
        fi
        sleep 1
        ((count++))
    done
    
    # Now wait for the rollout to complete
    if oc rollout status deployment/"${service}-okteto" --timeout=300s >/dev/null 2>&1; then
        log "✅ $service deployment ready"
        return 0
    else
        error "❌ $service deployment failed or timed out"
        return 1
    fi
}

# Check for port conflicts that would cause okteto SSH tunnel failures
check_port_conflicts() {
    # Allow bypass for advanced users
    if [[ "${OKTETO_SKIP_PORT_CHECK:-}" == "true" ]]; then
        warn "⚠️  Port conflict check bypassed"
        return 0
    fi

    log "🔎 Dynamically checking for port conflicts based on okteto.template.yaml..."

    if [[ ! -f "okteto/okteto.template.yaml" ]]; then
        warn "⚠️  okteto/okteto.template.yaml not found. Skipping dynamic port check."
        return
    fi

    # Dynamically extract local ports from the forward section of the okteto template
    local conflict_ports
    conflict_ports=($(grep -E '^\s*-\s*[0-9]{1,5}:[0-9]{1,5}' okteto/okteto.template.yaml | sed -e 's/^\s*-\s*//' -e 's/:.*//' | sort -u))

    if [[ ${#conflict_ports[@]} -eq 0 ]]; then
        log "✅ No ports to check in okteto.template.yaml."
        return
    fi
    
    log "   Ports to check: ${conflict_ports[*]}"

    local ports_in_use=()
    local port_processes=()
    
    for port in "${conflict_ports[@]}"; do
        # Validate port number
        if [[ ! "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
            warn "⚠️  Invalid port number: $port"
            continue
        fi

        local process_info=""
        local port_in_use=false

        # Try lsof first (most detailed)
        if command -v lsof >/dev/null 2>&1; then
            if lsof -i ":$port" >/dev/null 2>&1; then
                port_in_use=true
                process_info=$(lsof -i ":$port" 2>/dev/null | tail -1 | awk '{print $1, $2}')
            fi
        # Fallback to ss
        elif command -v ss >/dev/null 2>&1; then
            if ss -ln | grep -q ":$port "; then
                port_in_use=true
                process_info="(process details unavailable with ss)"
            fi
        # Fallback to netstat
        elif command -v netstat >/dev/null 2>&1; then
            if netstat -ln 2>/dev/null | grep -q ":$port "; then
                port_in_use=true
                process_info="(process details unavailable with netstat)"
            fi
        else
            warn "⚠️  No port checking tools available (lsof, ss, netstat)"
            return 0
        fi

        if [[ "$port_in_use" == "true" ]]; then
            ports_in_use+=("$port")
            port_processes+=("$process_info")
        fi
    done

    if [[ ${#ports_in_use[@]} -gt 0 ]]; then
        error "❌ Port conflicts detected that will cause okteto SSH tunnel failures:"
        for i in "${!ports_in_use[@]}"; do
            error "   Port ${ports_in_use[$i]} is occupied by: ${port_processes[$i]}"
        done
        error ""
        error "🔧 To fix: Stop the processes using these ports"
        error "   Most common fix: pkill -f 'port-forward'"
        error "   Or set: OKTETO_SKIP_PORT_CHECK=true (if you know what you're doing)"
        exit 1
    fi
    
    log "✅ No port conflicts detected."
}

# Ensure we're not running on production/stage clusters
check_cluster_safety() {
    # Allow bypass with warning
    if [[ "${OKTETO_SKIP_CLUSTER_SAFETY_CHECK:-}" == "true" ]]; then
        warn "🚨 Cluster safety check bypassed - ensure this is not production!"
        return 0
    fi
    
    local namespace=$(oc project -q 2>/dev/null || echo "")
    local cluster=$(oc config current-context 2>/dev/null || echo "")
    
    # Block obvious production/stage environments
    if [[ "$namespace" == *"prod"* ]] || [[ "$namespace" == *"stage"* ]] || 
       [[ "$cluster" == *"prod"* ]] || [[ "$cluster" == *"stage"* ]]; then
        error "🚨 SAFETY: Okteto development blocked on production/stage environment"
        error "   Namespace: $namespace"
        error "   Cluster: $cluster"
        error ""
        error "❌ This could replace production deployments with development code!"
        error "🔧 Switch to an ephemeral cluster for development"
        exit 1
    fi
    
    # Warn if not clearly ephemeral
    if [[ "$namespace" != *"ephemeral"* ]] && [[ "$cluster" != *"ephemeral"* ]]; then
        warn "⚠️  Not clearly an ephemeral environment:"
        warn "   Namespace: $namespace"
        warn "   Cluster: $cluster"
        warn "   Set OKTETO_SKIP_CLUSTER_SAFETY_CHECK=true if this is safe"
    fi
}


# Main okteto commands
okteto_up() {
    local daemon_mode=false
    local wait_rollout=false
    local service=""
    
    # Parse flags and arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d)
                daemon_mode=true
                shift
                ;;
            -w)
                wait_rollout=true
                shift
                ;;
            -*)
                error "Unknown flag: $1"
                exit 1
                ;;
            *)
                if [[ -n "$service" ]]; then
                    error "Multiple services specified: $service and $1"
                    exit 1
                fi
                service="$1"
                shift
                ;;
        esac
    done
    
    # Validate -w flag usage
    if [[ "$wait_rollout" == "true" && "$daemon_mode" != "true" ]]; then
        error "Flag -w can only be used with -d (daemon mode)"
        exit 1
    fi
    
    if [[ -z "$service" ]]; then
        warn "Sorry! Interactive service selection has been disabled to ensure reliable customizations."
        warn ""
        warn "Please specify a service name directly:"
        warn "  Usage: $0 up [options] <service>"
        warn ""
        warn "Available services:"
        for service_name in "${DEFAULT_SERVICES[@]}"; do
            warn "  • $service_name"
        done
        warn ""
        warn "Example: $0 up host-inventory-service-reads"
        warn ""
        warn "💡 This change ensures deployment customizations are always applied correctly!"
        exit 1
    fi
    
    # Validate the service exists in our list
    if [[ ! " ${DEFAULT_SERVICES[*]} " =~ " ${service} " ]]; then
        error "Invalid service: $service"
        error "Available services: ${DEFAULT_SERVICES[*]}"
        exit 1
    fi
    
    if [[ "$daemon_mode" == "true" ]]; then
        log "Starting development for service: $service (daemon mode)"
    else
        log "Starting development for service: $service"
    fi
    
    # Check if this specific service is already active
    if oc get deployment "${service}-okteto" >/dev/null 2>&1; then
        log "Service $service already in development mode (idempotent)"
        return 0
    fi
    
    # Disable ClowdApp reconciliation before starting development
    local clowdapp_was_disabled=$(check_clowdapp_status)
    if [[ "$clowdapp_was_disabled" != "true" ]]; then
        disable_clowdapp
    else
        log "ClowdApp reconciliation already disabled"
    fi
    
    # Apply customizations for the specified service
    scripts/customize_deployments.sh "$service" up
    
    # Update okteto.yaml with current namespace SCC settings and image info
    local namespace uid_range uid_start image_full image_name image_tag
    namespace=$(oc project -q)
    uid_range=$(oc get namespace "$namespace" -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.uid-range}' 2>/dev/null || echo "1000000000/10000")
    uid_start=$(echo "$uid_range" | cut -d'/' -f1)
    
    # Detect current image and tag from deployed Python service (not nginx)
    image_full=$(oc get deployment host-inventory-service-reads -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "quay.io/cloudservices/insights-inventory:latest")
    image_name=$(echo "$image_full" | cut -d':' -f1)
    image_tag=$(echo "$image_full" | cut -d':' -f2)
    
    log "Using image: $image_name:$image_tag"
    
    # Generate okteto.yaml from template with current namespace values
    log "Generating okteto.yaml from template for namespace $namespace (UID: $uid_start)"
    cp okteto/okteto.template.yaml okteto/okteto.yaml
    
    # Replace environment variable placeholders with actual values
    sed -i.tmp "s/\${OKTETO_USER_ID}/$uid_start/g; s/\${OKTETO_GROUP_ID}/$uid_start/g; s/\${OKTETO_FS_GROUP_ID}/$uid_start/g; s|\${OKTETO_IMAGE}|$image_name|g; s/\${OKTETO_TAG}/$image_tag/g" okteto/okteto.yaml
    rm -f okteto/okteto.yaml.tmp
    
    # Set the repo path for okteto
    export INSIGHTS_HOST_INVENTORY_REPO_PATH
    
    if [[ "$daemon_mode" == "true" ]]; then
        # Daemon mode: run in background with output redirected to local log file
        mkdir -p "$DAEMON_LOG_DIR"
        local log_file=$(get_daemon_log_file "$service")
        
        log "Starting $service in daemon mode, logs: $log_file"
        
        (
            okteto up --file okteto/okteto.yaml --namespace "$namespace" "$service" 2>&1
        ) > "$log_file" 2>&1 &
        
        if [[ "$wait_rollout" == "true" ]]; then
            # Wait for the deployment to be ready
            if wait_for_rollout "$service"; then
                log "🚀 $service is ready in daemon mode"
            else
                error "❌ $service failed to become ready"
                # Clean up local artifacts on failure
                cleanup_daemon_files "$service"
                return 1
            fi
        else
            log "🚀 $service started in daemon mode"
            log "💡 Use '$0 logs $service' to view logs"
            log "💡 Use '$0 up $service -d -w' to wait for rollout completion"
        fi
    else
        # Normal mode: run in foreground
        okteto up --file okteto/okteto.yaml --namespace "$namespace" "$service"
    fi
}

okteto_down() {
    local service="$1"  # Optional service parameter
    
    # Validate that only one service argument is provided
    if [[ $# -gt 1 ]]; then
        error "Only one service can be specified for down command"
        error "To stop all services, use: $0 down"
        error "To stop a specific service, use: $0 down <service>"
        exit 1
    fi
    
    if [[ -n "$service" ]]; then
        # Validate the service exists in our list
        if [[ ! " ${DEFAULT_SERVICES[*]} " =~ " ${service} " ]]; then
            error "Invalid service: $service"
            error "Available services: ${DEFAULT_SERVICES[*]}"
            exit 1
        fi
        
        # Check if this specific service is active
        if ! oc get deployment "${service}-okteto" >/dev/null 2>&1; then
            log "Service $service not in development mode (idempotent)"
            return 0
        fi
        
        log "Stopping development for service: $service"
        
        # Use existing okteto.yaml if available, otherwise create temporary one
        local created_temp_yaml=false
        if [[ ! -f "okteto/okteto.yaml" ]]; then
            cp okteto/okteto.template.yaml okteto/okteto.yaml
            # Use dummy values - actual values don't matter for cleanup operations
            sed -i.tmp "s/\${OKTETO_USER_ID}/1000000000/g; s/\${OKTETO_GROUP_ID}/1000000000/g; s/\${OKTETO_FS_GROUP_ID}/1000000000/g; s|\${OKTETO_IMAGE}|quay.io/cloudservices/insights-inventory|g; s/\${OKTETO_TAG}/latest/g" okteto/okteto.yaml
            rm -f okteto/okteto.yaml.tmp
            created_temp_yaml=true
        fi
        
        okteto down --file okteto/okteto.yaml --namespace "$(oc project -q)" "$service"
        
        # Clean up temporary okteto.yaml if we created it
        if [[ "$created_temp_yaml" == "true" ]]; then
            rm -f okteto/okteto.yaml
        fi
        
        # Clean up daemon artifacts for this service
        cleanup_daemon_files "$service"
        
        # Revert any deployment customizations for this service
        scripts/customize_deployments.sh "$service" down
        
        log "Service $service development stopped"
        # Note: Don't re-enable ClowdApp for individual service down
        return 0
    fi
    
    # Full down - handle all services
    local status=$(check_dev_status "${DEFAULT_SERVICES[@]}")
    local active=$(echo "$status" | cut -d'|' -f1)
    
    if [[ -z "$active" ]]; then
        log "No development containers active (idempotent)"
        # Still check if we need to re-enable ClowdApp
        local clowdapp_disabled=$(check_clowdapp_status)
        if [[ "$clowdapp_disabled" == "true" ]]; then
            enable_clowdapp
        fi
        # Clean up any leftover daemon artifacts even if no active containers
        cleanup_all_daemon_artifacts
        return 0
    fi
    
    # Use existing okteto.yaml if available, otherwise create temporary one
    local created_temp_yaml=false
    if [[ ! -f "okteto/okteto.yaml" ]]; then
        log "Creating temporary okteto.yaml for cleanup"
        cp okteto/okteto.template.yaml okteto/okteto.yaml
        # Use dummy values - actual values don't matter for cleanup operations
        sed -i.tmp "s/\${OKTETO_USER_ID}/1000000000/g; s/\${OKTETO_GROUP_ID}/1000000000/g; s/\${OKTETO_FS_GROUP_ID}/1000000000/g; s|\${OKTETO_IMAGE}|quay.io/cloudservices/insights-inventory|g; s/\${OKTETO_TAG}/latest/g" okteto/okteto.yaml
        rm -f okteto/okteto.yaml.tmp
        created_temp_yaml=true
    fi
    
    log "Stopping development containers: $active"
    okteto down --file okteto/okteto.yaml --namespace "$(oc project -q)" --all
    
    # Automated cleanup fallback for okteto bug
    log "Running automated cleanup of any remaining okteto deployments..."
    oc get deployments -o name | grep -- '-okteto$' | xargs -r oc delete >/dev/null 2>&1 || true
    oc get secrets -o name | grep '^secret/okteto-' | xargs -r oc delete >/dev/null 2>&1 || true  
    oc get pvc -o name | grep -- '-okteto$' | xargs -r oc delete >/dev/null 2>&1 || true
    
    log "All development containers cleaned up"
    
    # Clean up temporary okteto.yaml if we created it
    if [[ "$created_temp_yaml" == "true" ]]; then
        log "Cleaning up temporary okteto.yaml"
        rm -f okteto/okteto.yaml
    fi
    
    # Clean up local daemon artifacts after okteto down succeeds
    # The background okteto processes should have terminated naturally
    cleanup_all_daemon_artifacts
    
    # Re-enable ClowdApp reconciliation after stopping development
    local clowdapp_disabled=$(check_clowdapp_status)
    if [[ "$clowdapp_disabled" == "true" ]]; then
        enable_clowdapp
    else
        log "ClowdApp reconciliation already enabled"
    fi
}

okteto_exec() {
    [[ -z "$1" ]] && { error "Service name required"; exit 1; }
    local service="$1"; shift
    
    if ! oc get deployment "${service}-okteto" >/dev/null 2>&1; then
        error "Service '$service' not in development mode"
        error "Run: $0 up $service"
        exit 1
    fi
    
    # Use existing okteto.yaml if available, otherwise create temporary one
    local created_temp_yaml=false
    if [[ ! -f "okteto/okteto.yaml" ]]; then
        cp okteto/okteto.template.yaml okteto/okteto.yaml
        # Use dummy values - actual values don't matter for exec operations
        sed -i.tmp "s/\${OKTETO_USER_ID}/1000000000/g; s/\${OKTETO_GROUP_ID}/1000000000/g; s/\${OKTETO_FS_GROUP_ID}/1000000000/g; s|\${OKTETO_IMAGE}|quay.io/cloudservices/insights-inventory|g; s/\${OKTETO_TAG}/latest/g" okteto/okteto.yaml
        rm -f okteto/okteto.yaml.tmp
        created_temp_yaml=true
    fi
    
    okteto exec --file okteto/okteto.yaml --namespace "$(oc project -q)" "$service" -- "$@"
    
    # Clean up temporary okteto.yaml if we created it
    if [[ "$created_temp_yaml" == "true" ]]; then
        rm -f okteto/okteto.yaml
    fi
}

okteto_logs() {
    [[ -z "$1" ]] && { error "Service name required for logs command"; exit 1; }
    local service="$1"
    
    # Validate the service exists in our list
    if [[ ! " ${DEFAULT_SERVICES[*]} " =~ " ${service} " ]]; then
        error "Invalid service: $service"
        error "Available services: ${DEFAULT_SERVICES[*]}"
        exit 1
    fi
    
    local log_file=$(get_daemon_log_file "$service")
    
    # Check if the log file exists
    if [[ ! -f "$log_file" ]]; then
        error "No daemon log file found for service: $service"
        error "Service may not be running in daemon mode"
        error "Expected log file: $log_file"
        error "Start the service with: $0 up -d $service"
        exit 1
    fi
    
    log "Tailing logs for $service (Ctrl+C to exit)"
    log "Log file: $log_file"
    
    # Tail the local log file
    tail -f "$log_file"
}

okteto_group_up() {
    local wait_rollout=false
    local use_all_services=false
    local services=()
    
    # Parse flags and arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -w)
                wait_rollout=true
                shift
                ;;
            --all)
                use_all_services=true
                shift
                ;;
            -*)
                error "Unknown flag: $1"
                exit 1
                ;;
            *)
                services+=("$1")
                shift
                ;;
        esac
    done
    
    # Handle --all flag
    if [[ "$use_all_services" == "true" ]]; then
        if [[ ${#services[@]} -gt 0 ]]; then
            error "Cannot specify both --all and individual services"
            error "Use either: $0 group-up --all"
            error "Or: $0 group-up <service1> <service2> ..."
            exit 1
        fi
        services=("${DEFAULT_SERVICES[@]}")
    else
        # Validate at least one service is provided when not using --all
        if [[ ${#services[@]} -eq 0 ]]; then
            error "At least one service must be specified for group-up"
            error "Available services: ${DEFAULT_SERVICES[*]}"
            error "Or use: $0 group-up --all"
            exit 1
        fi
        
        # Validate all services exist in our list
        for service in "${services[@]}"; do
            if [[ ! " ${DEFAULT_SERVICES[*]} " =~ " ${service} " ]]; then
                error "Invalid service: $service"
                error "Available services: ${DEFAULT_SERVICES[*]}"
                exit 1
            fi
        done
    fi
    
    # Track results
    local failed_services=()
    local started_services=()
    local service_pids=()
    local services_to_start=()
    
    # Collect services that need to be started
    for service in "${services[@]}"; do
        # Skip if already in development mode
        if oc get deployment "${service}-okteto" >/dev/null 2>&1; then
            continue
        fi
        services_to_start+=("$service")
    done
    
    # Start all services in parallel
    for service in "${services_to_start[@]}"; do
        okteto_up -d "$service" >/dev/null 2>&1 &
        service_pids+=("$!")
    done
    
    # Wait for all services to complete and check their exit codes
    for i in "${!service_pids[@]}"; do
        local pid="${service_pids[$i]}"
        local service="${services_to_start[$i]}"
        
        if wait "$pid"; then
            started_services+=("$service")
        else
            failed_services+=("$service")
        fi
    done
    
    # Wait for rollout if requested
    if [[ "$wait_rollout" == "true" && ${#started_services[@]} -gt 0 ]]; then
        local timeout_services=()
        
        for service in "${started_services[@]}"; do
            if ! wait_for_rollout "$service" 2>/dev/null; then
                timeout_services+=("$service")
                cleanup_daemon_files "$service"
            fi
        done
        
        if [[ ${#timeout_services[@]} -gt 0 ]]; then
            echo "❌ Timed out services: ${timeout_services[*]}" >&2
        fi
        
        # Exit with error if any service failed
        if [[ ${#failed_services[@]} -gt 0 || ${#timeout_services[@]} -gt 0 ]]; then
            exit 1
        fi
    else
        # Exit with error if any service failed to start
        if [[ ${#failed_services[@]} -gt 0 ]]; then
            exit 1
        fi
    fi
}

show_help() {
    cat >&2 << EOF
Usage: okteto-dev.sh {up|group-up|down|check|exec|logs} [options] [service]

Configuration:
  INSIGHTS_HOST_INVENTORY_REPO_PATH (required) - Path to your local insights-host-inventory repository
  Current: ${INSIGHTS_HOST_INVENTORY_REPO_PATH:-"<NOT SET>"}
  
  CLOWDAPP_NAME (optional) - Override ClowdApp name
  Current: $CLOWDAPP_NAME

Commands:
  up [options] <service> - Start development for one service
                          Service name is required
                          Options:
                            -d  Start in daemon mode (background)
                            -w  Wait for rollout completion (requires -d)
                          Automatically disables ClowdApp reconciliation
  group-up [options] <service1> <service2> ... - Start multiple services in daemon mode
                          All services run in background with no console output
                          Options:
                            --all  Start all available services
                            -w     Wait for all services to be ready before returning
                          Automatically disables ClowdApp reconciliation
  down [service]         - Stop development containers
                          No service: stop all development containers & re-enable ClowdApp
                          With service: stop that specific service only
  check [services...]    - Show development status including ClowdApp state
  exec <service> [cmd]   - Execute command in development container
  logs <service>         - Tail logs for a service started in daemon mode

Available Services:
  ${DEFAULT_SERVICES[*]}

Examples:
  okteto-dev.sh up host-inventory-service-reads          # Start in foreground
  okteto-dev.sh up -d host-inventory-service-reads       # Start in daemon mode
  okteto-dev.sh up -d -w host-inventory-service-reads    # Start in daemon mode and wait
  okteto-dev.sh group-up host-inventory-service-reads host-inventory-service-writes
                                                         # Start multiple services in background
  okteto-dev.sh group-up -w host-inventory-service-reads host-inventory-service-writes
                                                         # Start multiple services and wait
  okteto-dev.sh group-up --all                          # Start all available services
  okteto-dev.sh group-up --all -w                       # Start all services and wait
  okteto-dev.sh logs host-inventory-service-reads        # View daemon logs
  okteto-dev.sh check                                    # Show status
  okteto-dev.sh exec host-inventory-service-reads bash   # Connect to container
  okteto-dev.sh down                                     # Stop all development
  okteto-dev.sh down host-inventory-service-reads        # Stop specific service only

Daemon Mode:
  Services started with -d run in the background and log to ${DAEMON_LOG_DIR}/
  Use the 'logs' command to view okteto output from daemon mode services.
  The -w flag waits for the Kubernetes rollout to complete before returning.

Group Mode:
  The group-up command starts multiple services simultaneously in daemon mode.
  All services run in the background with output suppressed unless there's an error.
  Use -w to wait for all services to be ready before the command returns.

ClowdApp Management:
  This script automatically manages ClowdApp reconciliation to ensure proper
  deployment scaling. ClowdApp is disabled during development and re-enabled
  when development stops.

Safety Features:
  • Port conflict detection for common dev ports (8080, 8443, 9229, 5005, etc.)
  • Production/stage cluster protection
  
Environment Variables:
  INSIGHTS_HOST_INVENTORY_REPO_PATH  # Required: Path to your local repo
  OKTETO_SKIP_PORT_CHECK=true        # Skip port conflict check  
  OKTETO_SKIP_CLUSTER_SAFETY_CHECK=true  # Skip cluster safety check

Troubleshooting:
  Port conflicts: pkill -f 'port-forward'
  Wrong cluster: Switch to ephemeral environment
EOF
}

# Main function
main() {
    # Basic checks
    if ! oc whoami >/dev/null 2>&1; then
        error "Not logged into OpenShift"
        exit 1
    fi
    
    if ! command -v okteto >/dev/null 2>&1; then
        error "Okteto CLI not found"
        exit 1
    fi
    
    # Validate that we successfully loaded services from template
    if [[ ${#DEFAULT_SERVICES[@]} -eq 0 ]]; then
        error "No services found in okteto.template.yaml"
        error "Please check that the template file contains a 'dev:' section with service definitions"
        exit 1
    fi
    
    # Debug: show loaded services (suppress for group-up to keep output quiet)
    if [[ "${1:-up}" != "group-up" ]]; then
        log "Found ${#DEFAULT_SERVICES[@]} services in okteto.template.yaml: ${DEFAULT_SERVICES[*]}"
    fi
    
    # Clean up any existing backup files from previous runs
    rm -f okteto/okteto.yaml.bak okteto/okteto.yaml-e okteto/okteto.yaml.tmp
    
    # Verify repo path is set and exists
    if [[ -z "$INSIGHTS_HOST_INVENTORY_REPO_PATH" ]]; then
        warn "🔧 Almost ready! Just need to set up your local repository path first."
        warn ""
        warn "Please set INSIGHTS_HOST_INVENTORY_REPO_PATH to your local insights-host-inventory repository:"
        warn "  export INSIGHTS_HOST_INVENTORY_REPO_PATH=/path/to/your/insights-host-inventory"
        warn ""
        warn "Then you can run:"
        warn "  $0 up host-inventory-service-reads"
        warn ""
        warn "💡 Tip: Add the export to your ~/.bashrc or ~/.zshrc to make it permanent!"
        exit 1
    fi
    
    if [[ ! -d "$INSIGHTS_HOST_INVENTORY_REPO_PATH" ]]; then
        error "Insights repo path not found: $INSIGHTS_HOST_INVENTORY_REPO_PATH"
        error "Please verify the path exists and contains your insights-host-inventory repository"
        exit 1
    fi
    
    # Check if we're running on a safe (ephemeral) cluster
    check_cluster_safety || exit 1

    # Check if common ports are in use (Okteto typically uses these for SSH tunnels)
    check_port_conflicts || exit 1
    
    # Handle commands
    case "${1:-up}" in
        up)       shift; okteto_up "$@" ;;
        group-up) shift; okteto_group_up "$@" ;;
        down)     shift; okteto_down "$@" ;;
        check)    shift; show_status "$@" ;;
        exec)     shift; okteto_exec "$@" ;;
        logs)     shift; okteto_logs "$@" ;;
        -h|--help|help) show_help ;;
        *) error "Unknown command: $1"; show_help; exit 1 ;;
    esac
}

main "$@" 