CXXFLAGS      = -std=c++11 -W -Wall -Wno-variadic-macros \
			-pedantic -g -Wshadow -Wpointer-arith -Wcast-qual -fpermissive \
			-I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib \
			-pthread -I/usr/local/include
OPENSSL_DIR = /opt/openssl/1.0.2n
LDLIBS = -lssl -lcrypto -lrt -ldl -L/usr/local/lib -lprotobuf -pthread -lpthread
LDFLAGS = -Wl,-rpath -Wl,$(OPENSSL_DIR)
TARGETS = main_microcsr main_microcert


.PHONY: all
all: protoc_middleman demo.pb.o demo
	rm -f *.o *.gch ../*.o

demo: demo.o demo.pb.o
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

demo.o: demo.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

demo.pb.o: demo.pb.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: protoc_middleman
protoc_middleman: demo.proto
	protoc $$PROTO_PATH --cpp_out=. demo.proto