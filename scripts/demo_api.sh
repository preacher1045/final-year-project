#!/bin/bash
# Network Traffic Analyzer - API Quick Start Guide
# This script demonstrates how to use the API with the test PCAP file

set -e

BASE_URL="http://127.0.0.1:5000"
PROJECT_DIR="/home/schoolboy/projects/network_traffic_analyzer"

echo ""
echo "=================================================================================================="
echo "Network Traffic Analyzer - REST API Integration Demo"
echo "=================================================================================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper function to make requests
call_api() {
    local method=$1
    local endpoint=$2
    local data=$3
    local description=$4
    
    echo -e "${BLUE}→ ${description}${NC}"
    
    if [ "$method" = "GET" ]; then
        curl -s "$BASE_URL$endpoint" | python3 -m json.tool 2>/dev/null | head -30
    else
        if [ -z "$data" ]; then
            curl -s -X "$method" "$BASE_URL$endpoint" | python3 -m json.tool 2>/dev/null | head -30
        else
            curl -s -X "$method" "$BASE_URL$endpoint" -H "Content-Type: application/json" -d "$data" | python3 -m json.tool 2>/dev/null | head -30
        fi
    fi
    
    echo ""
}

# Check if server is running
echo -e "${YELLOW}1. Checking if API server is running...${NC}"
if curl -s "$BASE_URL/health" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ API server is running at $BASE_URL${NC}"
else
    echo -e "${YELLOW}ℹ API server not detected. Starting it now...${NC}"
    cd "$PROJECT_DIR"
    python3 api/api_server.py --mode pcap --pcap data/raw/pcapng/test_net_traffic.pcapng &
    sleep 3
    echo -e "${GREEN}✓ API server started${NC}"
fi

echo ""
echo -e "${YELLOW}2. Testing Health & Status Endpoints${NC}"
echo "---"
call_api "GET" "/health" "" "Check API Health"
call_api "GET" "/api/status" "" "Get System Status"

echo ""
echo -e "${YELLOW}3. Testing Metrics Endpoints${NC}"
echo "---"
call_api "GET" "/api/metrics/?limit=2" "" "List Metrics (first 2 windows)"
call_api "GET" "/api/metrics/0" "" "Get Specific Window (ID=0)"
call_api "GET" "/api/metrics/summary" "" "Get Metrics Summary"

echo ""
echo -e "${YELLOW}4. Testing Anomalies Endpoints${NC}"
echo "---"
call_api "GET" "/api/anomalies/?limit=3" "" "List Anomalies (first 3)"
call_api "GET" "/api/anomalies/by-type" "" "Get Anomalies Grouped by Type"
call_api "GET" "/api/anomalies/top?limit=3" "" "Get Top 3 Anomalies"

echo ""
echo -e "${YELLOW}5. Testing Baselines Endpoints${NC}"
echo "---"
call_api "GET" "/api/baselines/" "" "List All Baselines"
call_api "GET" "/api/baselines/bandwidth" "" "Get Bandwidth Baseline"
call_api "GET" "/api/baselines/stats" "" "Get Baseline Statistics"

echo ""
echo -e "${YELLOW}6. Testing Control Endpoints${NC}"
echo "---"
call_api "GET" "/api/control/status" "" "Get Control Status"
call_api "GET" "/api/control/config" "" "Get Configuration"
call_api "GET" "/api/control/ping" "" "Ping"

echo ""
echo "=================================================================================================="
echo -e "${GREEN}✓ API Demo Complete!${NC}"
echo "=================================================================================================="
echo ""
echo "API Documentation: API_DOCUMENTATION.md"
echo "API Server: http://127.0.0.1:5000"
echo ""
echo "Next Steps:"
echo "  1. Modify PCAP file path via --pcap flag"
echo "  2. Switch to live mode via --mode live --interface eth0"
echo "  3. Integrate with monitoring/dashboard tools"
echo "  4. Set up webhook alerting via /api/control/logs"
echo ""
