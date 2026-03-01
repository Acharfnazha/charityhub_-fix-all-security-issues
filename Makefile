# ─────────────────────────────────────────────
#  CharityHub - Makefile
# ─────────────────────────────────────────────

CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
TARGET   = charityhub
SRC      = main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)
	@echo ""
	@echo "  ✓ Build successful! Run with: ./$(TARGET)"
	@echo ""

clean:
	rm -f $(TARGET) *.o

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
