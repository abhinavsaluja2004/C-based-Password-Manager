CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

TARGET = password_manager
SOURCES = main.cpp
HEADERS = main.h

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(SOURCES) $(HEADERS)
	$(CXX) $(CXXFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

# Clean target
clean:
	rm -f $(TARGET)

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install libssl-dev

# Install dependencies (CentOS/RHEL/Fedora)
install-deps-rhel:
	sudo yum install openssl-devel

# Install dependencies (macOS)
install-deps-mac:
	brew install openssl
	@echo "On macOS, you may need to set:"
	@echo "export LDFLAGS=\"-L/usr/local/opt/openssl/lib\""
	@echo "export CPPFLAGS=\"-I/usr/local/opt/openssl/include\""

# Run the program
run: $(TARGET)
	./$(TARGET)

.PHONY: all clean install-deps install-deps-rhel install-deps-mac run
