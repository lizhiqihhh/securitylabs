#include "./sniffer.h"

int main(int argc, char *argv[]) {
	
    // 参数校验
    if (argc < 2) {
        printf("Hint: ./sniffer interfaceName(ens33 et.)\n");
        exit(0);
    }

    // 设置网卡混杂模式
    set_promiscuous_mode(argv[1]);

    // 开始嗅探
	printf("Start sniffer...\n");
    sniffer();

    return 0;
}

// 设置网卡混杂模式
void set_promiscuous_mode(char *interface_name) {
    int fd;
    
    // 建立特殊 socket
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0) {
        printf(">>>Please run the program in the root mode<<<\n");
        exit(0);
    }

    // ifreq
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface_name, strlen(interface_name) + 1);

    // 接受网卡的信息
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        printf(">>>Can't get info from the interface!\n");
        exit(0);
    }

    // 更改flags为混杂模式
    ifr.ifr_flags |= IFF_PROMISC;
    
    // 设置混杂模式
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
        printf(">>>Can't set the promisc flag to interface!<<<\n");
        exit(0);
    }

    printf(">>>Set to promiscuous mode finished.<<<\n");
}

// 嗅探
void sniffer() {
	int count = 100;
    int sock, bytes, i;
    socklen_t len;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in addr;
    struct iphdr *ip;
    struct tcphdr *tcp;
	struct timeval timeout;
	FILE *fp;
	fp = fopen("log.txt","w");
	if (!fp){
	printf("Open file failed.\n");
	}
    // 打开socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1) {
        printf(">>>Please run the program in the root mode<<<\n");
        exit(0);
    }

    // 开始嗅探
    while (count--) {
        // 清空结构体
        memset(buffer, 0, sizeof(buffer));
	timeout.tv_sec == 10;
	timeout.tv_usec = 0;
        // 接收数据
        bytes = recvfrom(sock, (char *) buffer, sizeof(buffer), 0, NULL, NULL);

        printf("\n");
        //输出接收到的字节序列
        for (i = 0; i < bytes; i++) {
            printf("%02x ", (unsigned char) buffer[i]);

            if ((i + 1) % 16 == 0) {
                printf("\n");
            }
        }

        fprintf(fp,"\n");
printf("\n******************************************************************\n");
        fprintf(fp,"\n\t\tReceived      %5d bytes\n", bytes);

        ip = (struct iphdr *) buffer;
        fprintf(fp,"\t\tIPhead-len      %5d \n", ip->tot_len);
        fprintf(fp,"\t\tProtocol         %5d\n",ip->protocol);

        tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
        fprintf(fp,"\t\tSrc address:  ");

        for (i = 0; i < 4; i++) {
						if (i == 3)fprintf(fp,"%03d   ",(unsigned char) *((char *)(&ip->saddr)+i));
						else
            	fprintf(fp,"%03d.", (unsigned char) *((char *) (&ip->saddr) + i));
        }
	fprintf(fp,"(");
        for (i = 0; i < 4; i++) {
            fprintf(fp,"%02x ", (unsigned char) *((char *) (&ip->saddr) + i));
        }

        fprintf(fp,")\n\t\tDest address: ");

        for (i = 0; i < 4; i++) {
						if (i == 3)fprintf(fp,"%03d   ",(unsigned char) *((char *)(&ip->saddr)+i));
						else
            fprintf(fp,"%03d.",(unsigned char) *((char *) (&ip->daddr) + i));
        }

        fprintf(fp,"(");

        for (i = 0; i < 4; i++) {
            fprintf(fp,"%02x ",(unsigned char) *((char *) (&ip->daddr) + i));
        }

        fprintf(fp,")\n");

        fprintf(fp,"\t\tSource port \t\t%d\n", ntohs(tcp->source)); 
		fprintf(fp,"\t\tDest port \t\t%d \n", ntohs(tcp->dest)); 
		fprintf(fp,"\t\tFIN:%d SYN:%d RST:%d \n\t\tPSH:%d ACK:%d URG:%d \n", ntohs(tcp->fin) && 1, ntohs(tcp->syn) && 1, ntohs(tcp->rst) && 1, ntohs(tcp->psh) && 1, ntohs(tcp->ack) && 1, ntohs(tcp->urg) && 1);
		printf("*************************************************\n");
		printf("Finished sniffer...\n");
    }
	fclose(fp);
}
