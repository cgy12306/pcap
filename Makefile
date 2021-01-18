LDLIBS += -lpcap

all: packet-stat

pcap-test: packet-stat.cpp

clean:
	rm -f packet-stat *.o

