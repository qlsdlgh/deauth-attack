# Makefile for compiling deauth-attack

# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++11 -Wall

# Include pcap library
LDFLAGS = -lpcap

# Source files
SRC = deauth-attack.cpp

# Output executable
TARGET = deauth-attack

# Default target
all: $(TARGET)

# Rule to build the target
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

# Clean rule
clean:
	rm -f $(TARGET)

.PHONY: all clean