#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Print functions
print_status() {
    echo -e "${BLUE}[STATUS]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if port is in use
check_port() {
    local pid=$(lsof -Pi :$1 -sTCP:LISTEN -t)
    if [ ! -z "$pid" ]; then
        print_status "Port $1 is in use by process $pid. Killing process..."
        kill -9 $pid
        sleep 1
        print_success "Port $1 has been freed"
    fi
}

# Clean install function
clean_install() {
    if [ -d "client/node_modules" ]; then
        print_status "Cleaning node_modules..."
        rm -rf "client/node_modules"
    fi
    if [ -f "client/package-lock.json" ]; then
        rm -f "client/package-lock.json"
    fi
    print_status "Installing dependencies..."
    cd client && npm install
    cd ..
}

# Cleanup function
cleanup() {
    print_status "Shutting down client..."
    if [ ! -z "$CLIENT_PID" ]; then
        kill $CLIENT_PID 2>/dev/null
    fi
    exit 0
}

# Register cleanup
trap cleanup SIGINT SIGTERM

# Main execution
print_status "Setting up development environment..."

# Check port
check_port 3000

# Check for clean flag
if [ "$1" == "--clean" ]; then
    print_status "Performing clean install..."
    clean_install
else
    print_status "Skipping clean install..."
fi

# Start frontend
print_status "Starting development server..."
cd client
npm start &
CLIENT_PID=$!
cd ..

# Keep script running
print_success "Development environment is ready!"
print_status "Frontend: http://localhost:3000"
print_status "Press Ctrl+C to stop the server"

# Wait for Ctrl+C
wait
