CXX ?= $(CROSS_COMPILE)g++

DAEMON = ipmid
DAEMON_OBJ = $(DAEMON).o
LIB_OBJ = apphandler.o
LIBS = libapphandler.so

INC_FLAG += $(shell pkg-config --cflags glib-2.0 gio-unix-2.0) -I. -O2 --std=gnu++11
LIB_FLAG += $(shell pkg-config --libs glib-2.0 gio-unix-2.0) -rdynamic
IPMID_PATH ?= -DHOST_IPMI_LIB_PATH=\"/usr/lib/host-ipmid/\" 

all: $(DAEMON) $(LIBS)

%.o: %.C
	$(CXX) -fpic -c $< $(CXXFLAGS) $(INC_FLAG) $(IPMID_PATH) -o $@

$(LIBS): $(LIB_OBJ)
	$(CXX) $^ -shared $(LDFLAGS) $(LIB_FLAG) -o $@

$(DAEMON): $(DAEMON_OBJ)
	$(CXX) $^ $(LDFLAGS) $(LIB_FLAG) -o $@ -ldl

clean:
	rm -f $(DAEMON) *.o *.so
