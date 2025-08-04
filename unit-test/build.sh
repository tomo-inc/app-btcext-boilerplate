#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Building BBN Unit Tests...${NC}"

# Create build directory
mkdir -p build
cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Debug

# Build
make -j$(nproc)

echo -e "${GREEN}Build completed successfully!${NC}"

# Run tests
echo -e "${YELLOW}Running tests...${NC}"
./bbn_tests

echo -e "${GREEN}Tests completed!${NC}"