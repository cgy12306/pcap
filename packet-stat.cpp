#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <map>
using namespace std;
struct Param {
	char* dev_{nullptr};

	bool parse(int argc, char* argv[]) {
		if (argc != 2) {
			usage();
			return false;
		}
		dev_ = argv[1];
		return true;
	}

	static void usage() {
		printf("syntax: packet-stat <pcap file>\n");
		printf("sample: packet-stat test.pcap\n");
	}
};


int main(int argc, char* argv[]) {
	Param param;
	if (!param.parse(argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_offline(param.dev_, errbuf);
	
	map<int, vector<int>> ipv4_stat;
	map<int, vector<int>>::iterator iter;
	map<int, vector<int>>::iterator iter2;
	u_int32_t sip, dip;
	int tx_packet = 0, tx_byte = 0, rx_packet = 0, rx_byte = 0;

	if (pcap == nullptr) {
		fprintf(stderr, "pcap_open_offline(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		memcpy(&sip, packet+0x1a, 4);
		memcpy(&dip, packet+0x1e, 4);

		iter = ipv4_stat.find(sip);
		if(iter == ipv4_stat.end()){					//not found, then make map
			tx_byte = header->caplen;
			ipv4_stat[sip] = vector<int>{1, tx_byte, rx_packet, rx_byte};

			iter2 = ipv4_stat.find(dip);
			if(iter2 == ipv4_stat.end()){
				ipv4_stat[dip] = vector<int>{0, 0, 1, (int)header->len};
			}
			else{
				iter2->second[2]++;
				iter2->second[3] += (int)header->len;
			}

		}
		else{										//find
			iter->second[0]++;
			iter->second[1] += header->caplen;
			iter2 = ipv4_stat.find(dip);
			if(iter2 == ipv4_stat.end()){
				ipv4_stat[dip] = vector<int>{0, 0, 1, (int)header->len};
			}
			else{
				iter2->second[2]++;
				iter2->second[3] += (int)header->len;
			}
		}
	}
	printf("==============================================================================\n");
	for(iter=ipv4_stat.begin();iter!=ipv4_stat.end();iter++)
		printf("ip: %d\ttx_packet: %d\ttx_byte: %d\trx_packet: %d\trx_byte: %d\n", iter->first, iter->second[0], iter->second[1], iter->second[2], iter->second[3]);
	printf("==============================================================================\n");

	pcap_close(pcap);
}

