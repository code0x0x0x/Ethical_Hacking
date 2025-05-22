#!/bin/bash

# Function to log messages
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Function to check if the script is running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log "Error: This script must be run as root."
        exit 1
    fi
}

# Function to check if a file exists and is writable
check_file() {
    if [ ! -w "$1" ]; then
        log "Error: File $1 does not exist or is not writable."
        exit 1
    fi
}

# Function to enable anti-cold boot settings
enable_anti_cold_boot() {
    log "Starting anti-cold boot configuration..."
    
    # Check if /proc/sys/vm/ exists
    if [ ! -d "/proc/sys/vm/" ]; then
        log "Error: /proc/sys/vm/ directory not found. This script is intended for Linux systems."
        exit 1
    fi
    
    # Dry-run mode: Print actions without executing
    if [ "$1" = "--dry-run" ]; then
        log "Dry-run mode enabled. No changes will be made."
        log "Would run: swapoff -a"
        log "Would run: swapon -a"
        log "Would run: echo 1024 > /proc/sys/vm/min_free_kbytes"
        log "Would run: echo 3 > /proc/sys/vm/drop_caches"
        log "Would run: echo 1 > /proc/sys/vm/oom_kill_allocating_task"
        log "Would run: echo 1 > /proc/sys/vm/overcommit_memory"
        log "Would run: echo 0 > /proc/sys/vm/oom_dump_tasks"
        return
    fi
    
    # Execute commands with error handling
    swapoff -a || { log "Error: Failed to disable swap."; exit 1; }
    swapon -a || { log "Error: Failed to enable swap."; exit 1; }
    echo 1024 > /proc/sys/vm/min_free_kbytes || { log "Error: Failed to set min_free_kbytes."; exit 1; }
    echo 3 > /proc/sys/vm/drop_caches || { log "Error: Failed to drop caches."; exit 1; }
    echo 1 > /proc/sys/vm/oom_kill_allocating_task || { log "Error: Failed to set oom_kill_allocating_task."; exit 1; }
    echo 1 > /proc/sys/vm/overcommit_memory || { log "Error: Failed to set overcommit_memory."; exit 1; }
    echo 0 > /proc/sys/vm/oom_dump_tasks || { log "Error: Failed to set oom_dump_tasks."; exit 1; }
    
    log "Anti-cold boot successfully enabled."
}

# Main function
main() {
    check_root
    
    case "$1" in
        --dry-run)
            enable_anti_cold_boot "--dry-run"
            ;;
        *)
            enable_anti_cold_boot
            ;;
    esac
}

# Execute main function with arguments
main "$@"
