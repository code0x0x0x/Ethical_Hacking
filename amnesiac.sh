#!/bin/bash

# Amnesiac system restore script
# WARNING: This will wipe all current system data and restore from backup
# Usage: ./amnesiac.sh [--dry-run] [backup_path]

set -euo pipefail

LOG_FILE="/var/log/amnesiac_restore.log"
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

cleanup_script_logs() {
    log "Cleaning up script logs..."
    if [ -f "$LOG_FILE" ]; then
        shred -n 1 -zu "$LOG_FILE"
        log "Deleted script log file: $LOG_FILE"
    else
        log "No script log file found to delete."
    fi
}

clear_logs() {
    log "Clearing system logs..."
    # Common log directories to clear
    LOG_DIRS=(
        "/var/log"
        "/var/log/journal"
    )

    for dir in "${LOG_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            find "$dir" -type f \( -name "*.log" -o -name "*.gz" -o -name "*.1" \) -delete
            log "Cleared logs in $dir"
        fi
    done

    # Additional cleanup for systemd journals
    if command -v journalctl &>/dev/null; then
        journalctl --vacuum-time=1s
        log "Cleared systemd journals"
    fi
}

cleanup() {
    if mountpoint -q /mnt/ramdisk; then
        umount /mnt/ramdisk || true
    fi
    rmdir /mnt/ramdisk || true
    log "Cleanup complete."
}

trap cleanup EXIT INT TERM

confirm_restore() {
    read -p "WARNING: This will wipe ALL system data and restore from backup. Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Aborted."
        exit 1
    fi
}

dry_run() {
    log "Dry run: Simulating restore from $BACKUP_SOURCE"
    log "Would execute: tar -xzf $BACKUP_SOURCE -C /mnt/ramdisk"
    log "Would execute: rsync -a /mnt/ramdisk/ /"
    log "Dry run complete. No changes made."
    exit 0
}

validate_backup() {
    if ! tar -tzf "$BACKUP_SOURCE" &>/dev/null; then
        log "Error: Backup file is corrupt or invalid" >&2
        exit 1
    fi
    log "Backup validated successfully."
}

validate_restore() {
    if [ ! -f "/etc/passwd" ] || [ ! -d "/home" ]; then
        log "Error: Critical files/directories missing after restore" >&2
        exit 1
    fi
    log "Restore validated successfully."
}

restore_from_backup() {
    log "Starting system restore..."

    # Clear logs before restore
    clear_logs

    # Mount RAM disk to handle all operations in memory
    mount -t tmpfs -o size=2G tmpfs /mnt/ramdisk

    # Verify backup exists
    if [ ! -f "$BACKUP_SOURCE" ]; then
        log "Error: Backup file not found at $BACKUP_SOURCE" >&2
        exit 1
    fi

    # Wipe current system (excluding mounted filesystems)
    log "Wiping system..."
    find / -xdev -type f -exec shred -n 1 -zu {} \;
    find / -xdev -type d -empty -delete

    # Restore from backup
    log "Restoring from backup..."
    tar -xzf "$BACKUP_SOURCE" -C /mnt/ramdisk
    rsync -a /mnt/ramdisk/ /

    # Validate restore
    validate_restore

    # Clean up
    umount /mnt/ramdisk
    rmdir /mnt/ramdisk

    # Force sync and clear caches
    sync
    echo 3 > /proc/sys/vm/drop_caches

    # Clean up script logs before reboot
    cleanup_script_logs

    log "System restored from backup. Rebooting..."
    reboot
}

# Main execution
if [ "$1" = "--dry-run" ]; then
    BACKUP_SOURCE="${2:-/backup/system_backup.tar.gz}"
    dry_run
else
    BACKUP_SOURCE="${1:-/backup/system_backup.tar.gz}"
    confirm_restore
    validate_backup
    restore_from_backup
fi
