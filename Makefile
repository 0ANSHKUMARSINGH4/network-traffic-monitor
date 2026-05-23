CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -Wpedantic -D_DEFAULT_SOURCE -D__FAVOR_BSD
LDFLAGS = -lpcap

TARGET = traffic_monitor
SRCS = main.cpp CaptureEngine.cpp PacketParser.cpp TrafficLogger.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
