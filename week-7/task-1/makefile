CXXFLAGS      = -std=c++11 -W -Wall -Wno-variadic-macros \
			-pedantic -g -Wshadow -Wpointer-arith -Wcast-qual -fpermissive \
			-I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib \
			-pthread -I/usr/local/include
OPENSSL_DIR = /opt/openssl/1.0.2n
LDLIBS = -lssl -lcrypto -lrt -ldl -L/usr/local/lib -lprotobuf -pthread -lpthread
LDFLAGS = -Wl,-rpath -Wl,$(OPENSSL_DIR)
TARGETS = main_microcsr main_microcert


.PHONY: all
all: protoc_middleman csr.pb.o cauth
	rm -f *.o *.gch ../*.o

cauth: cauth.o csr.pb.o
	$(CXX) $(CXXFLAGS) $^ $(LDLIBS) -o $@

cauth.o: cauth.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

csr.pb.o: csr.pb.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY: protoc_middleman
protoc_middleman: csr.proto
	protoc $$PROTO_PATH --cpp_out=. csr.proto