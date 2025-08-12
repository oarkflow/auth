#!/bin/bash

# Simple monitoring script for the authentication service
# This script checks the health of the service and logs basic metrics

LOG_FILE="/var/log/auth-service-monitor.log"
SERVICE_URL="http://localhost:8080"
CHECK_INTERVAL=30  # seconds

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

check_service_health() {
    local response
    local http_code

    response=$(curl -s -w "HTTPSTATUS:%{http_code};TIME:%{time_total}" "$SERVICE_URL/health" 2>/dev/null)

    if [[ $? -eq 0 ]]; then
        http_code=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
        response_time=$(echo "$response" | grep -o "TIME:[0-9.]*" | cut -d: -f2)

        if [[ "$http_code" == "200" ]]; then
            log_message "✅ Service healthy - Response time: ${response_time}s"
            return 0
        else
            log_message "❌ Service unhealthy - HTTP $http_code"
            return 1
        fi
    else
        log_message "❌ Service unreachable"
        return 1
    fi
}

check_service_status() {
    local response
    response=$(curl -s "$SERVICE_URL/api/status" 2>/dev/null)

    if [[ $? -eq 0 ]]; then
        local status=$(echo "$response" | jq -r '.status' 2>/dev/null)
        local version=$(echo "$response" | jq -r '.version' 2>/dev/null)
        log_message "📊 Service status: $status, Version: $version"
    fi
}

check_disk_space() {
    local usage
    usage=$(df -h . | awk 'NR==2 {print $5}' | sed 's/%//')

    if [[ $usage -gt 80 ]]; then
        log_message "⚠️  Disk usage high: ${usage}%"
    fi
}

check_memory_usage() {
    local memory_usage
    memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')

    if (( $(echo "$memory_usage > 80" | bc -l) )); then
        log_message "⚠️  Memory usage high: ${memory_usage}%"
    fi
}

send_alert() {
    local message=$1
    # In production, integrate with your alerting system
    # e.g., send email, Slack notification, PagerDuty, etc.
    log_message "🚨 ALERT: $message"
}

main() {
    log_message "🔄 Starting monitoring check"

    # Check service health
    if ! check_service_health; then
        send_alert "Authentication service is down or unhealthy"
    fi

    # Check service status
    check_service_status

    # Check system resources
    check_disk_space
    check_memory_usage

    log_message "✅ Monitoring check completed"
}

# Run monitoring check
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || LOG_FILE="./auth-monitor.log"

    if [[ "$1" == "--daemon" ]]; then
        log_message "🚀 Starting monitoring daemon"
        while true; do
            main
            sleep $CHECK_INTERVAL
        done
    else
        main
    fi
fi
