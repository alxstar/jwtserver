CXX = g++
SOURCES = $(shell find . -name '*.cpp')
OBJECTS = $(SOURCES:.cpp=.o)
TARGET = jwtserver

CPPFLAGS = $(INCLUDES) -c -MMD 
LDFLAGS = $(LIBS) -lssl -lcrypto -lboost_system -pthread 
DEPS = *.d

-include $(DEPS)

all: $(OBJECTS) $(TARGET)
	
.cpp.o: $(shell find . -name '*.h')
	$(CXX) $(CPPFLAGS) $< -o $@

$(TARGET): $(OBJECTS)
	$(CXX) -o $@ $(OBJECTS) $(LDFLAGS)  

clean:
	rm -f $(OBJECTS) $(TARGET) $(DEPS)
