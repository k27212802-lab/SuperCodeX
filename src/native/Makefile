# SuperCodeX v9.281.492 C++ Application Makefile
# Compiles supercodex.exe standalone C++ application

CXX = g++
CXXFLAGS = -O3 -std=c++17 -Wall -Wextra -I.
TARGET = supercodex.exe

SRCS = main.cpp pe_parser.cpp scanner.cpp decompiler.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)
	@echo "[SUCCESS] Built standalone C++ application: $(TARGET)"

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
