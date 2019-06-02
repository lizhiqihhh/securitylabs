#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/select.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LAN_HOST_NUMBER 100 
#define BUFFER_SIZE 1024
#define CHAR_BUFFER_SIZE 100
#define DEFAULT_THREAD_NUMBER 6
#define DEFAULT_START_PORT 22
#define DEFAULT_END_PORT 1024

void showLanHostAndIp();
int TCPportScanner();
int scan(char *, int, int, int,int);
void *scanThreadFunc(void *args);
typedef struct {
	char ip[40];
	char name[40];
}Host;
typedef struct {
    int pNum;
    int port;
    int end;
    char *ip;
}Args, *ScanArgsPtr;

Host LocalAreaNet[MAX_LAN_HOST_NUMBER];
int Num_of_hosts = 0;
int visited[1024] ={0};

void clear_zero()
{
	int i;
	for(i = 0;i < 1024;i++)
	visited[i] = 0;
}
int main(int argc, char *argv[])
{
	
    strcpy(LocalAreaNet[Num_of_hosts].name,"LocalHost");
    strcpy(LocalAreaNet[Num_of_hosts].ip,"127.0.0.1");
    Num_of_hosts++;
    /*在终端没有给出端口号起始和终止位置时，使用默认值*/
    int startport = DEFAULT_START_PORT;
    int endport = DEFAULT_END_PORT;
    int thread_n = DEFAULT_THREAD_NUMBER;
    int i;

    if (argc < 2){
        printf("Please give right args' format: \n");
        printf("1. ./scanner -lan localaddress\n");
        printf("2. ./scanner -ip ipAddress\n");
        return 0;
    }
    //scanning the local hosts
    if (!strcmp(argv[1],"-lan")){
        showLanHostAndIp();//显示局域网主机名
	
        if (argc > 2){
            startport = atoi(argv[2]);//如果输入了端口起始号
        }
        if (argc > 3){
            endport = atoi(argv[3]);
        }
        if (argc > 4){
            thread_n = atoi(argv[4]);    
        }
        //scan one by one
        scan(LocalAreaNet[0].ip, startport, endport, thread_n,2);
        clear_zero();
        for (i = 1;i < Num_of_hosts; i++){
            scan(LocalAreaNet[i].ip, startport, endport, thread_n,1);
            clear_zero();
        }
				
    }
    else if(!strcmp(argv[1],"-ip")){
       if (argc > 3){
        startport = atoi(argv[3]);//端口起始号
        
       endport = atoi(argv[4]);
       
       thread_n = atoi(argv[5]);}    
        //scan just one time 
       scan(argv[2], startport, endport, thread_n,2);
       clear_zero();
    }
    else {
        printf("Unknown params.\n");
    }
    return 0;
}
// 显示局域网主机名和IP
void showLanHostAndIp()
{
    //文件结构体
    FILE  *hostIPfile;
    // 缓冲区
    char buffer1[CHAR_BUFFER_SIZE], buffer2[CHAR_BUFFER_SIZE];
    char *temp = NULL;
    int i;
    printf("\n");
    //sudo arp -a | cut -d "?" -f 1 >hip.txt
    //sudo arp -a | cut -d "?" -f 2 >hip.txt 
    hostIPfile = fopen("hip.txt","r");
    if( !hostIPfile){
        printf("open hip.txt failed!\n");
        exit(0);
    }
    //read the file and store into the structural body
    while (fgets(buffer1, CHAR_BUFFER_SIZE,hostIPfile)){
        if (buffer1[strlen(buffer1) - 1] == '\n')buffer1[strlen(buffer1) - 1] = '\0';
	
        temp = strtok(buffer1,")");
	strcpy(buffer2,strtok(NULL,")"));
        if (buffer2[strlen(buffer2) - 1] == '\n')buffer2[strlen(buffer2) - 1] = '\0';/*printf("buffer 1 = %s,size(buffer) = %d\n",buffer1,strlen(buffer1));
	temp = strtok(buffer1,"(");
	strcpy(buffer1,strtok(NULL,"("));
	printf("buffer 1 = %s,size(buffer) = %d\n",buffer1,strlen(buffer1));*/
        strcpy(LocalAreaNet[Num_of_hosts].name,buffer2);
        strcpy(LocalAreaNet[Num_of_hosts].ip,buffer1);
        Num_of_hosts++;
    }
    //close the file
    fclose(hostIPfile);
    //输出局域网的主机信息
    printf("All the host info in Local area network:\n");
    printf("No\t \t  host_IP \t\t\t\t\thost_MAC\n");
    for (i = 0;i < Num_of_hosts;i++){
        printf("%d\t\t%-22s %38s\n",i + 1,LocalAreaNet[i].ip,LocalAreaNet[i].name);
    }
    printf("\n");

}
int scan_t(char *ip, int startport, int endport, int threadn,int type)
{
	char temp[CHAR_BUFFER_SIZE];
    
	strcpy(temp,ip);
	char *t =NULL;
	t= strtok(temp,"(");
	if (type == 1)
	printf("\n*********Scanning %s********\n",strtok(NULL,"("));
	else 
	printf("\n*********Scanning %s********\n",ip);
	int i ;
   	for (i = startport;i < endport;i++)
	{
		if (TCPportScanner(ip,i)){
			printf("----------port %5d -----------TCP Open\n",i);
		}
	}
}
int scan(char *ip, int startport, int endport, int threadn,int type)
{ // 线程结构体数组
    pthread_t *pthreads;
    // 线程参数结构体数组
    ScanArgsPtr argsA;
    int i;
    int pthreadNum = threadn;
    char temp[CHAR_BUFFER_SIZE];
    //输出log
	strcpy(temp,ip);
	char *t =NULL;
	t= strtok(temp,"(");
	if (type == 1)
	printf("\n*********Scanning %s**********\n",strtok(NULL,"("));
	else 
	printf("\n*********Scanning %s**********\n",ip);
    pthreads = (pthread_t *)malloc(sizeof(pthread_t) * pthreadNum);
    argsA = (ScanArgsPtr) malloc(sizeof(Args) * pthreadNum);
    //建立线程
    for (i = 0; i < pthreadNum; i++)
    {
        memset(&argsA[i], 0, sizeof(argsA[i]));
        argsA[i].pNum = pthreadNum;
        argsA[i].port = startport + 1;
        argsA[i].ip = ip;
        argsA[i].end = endport;

        if (pthread_create(&pthreads[i],NULL,scanThreadFunc,(void *)&argsA[i]) == -1){
            printf("Fail to create pthread. Try again,please!\n");
            return 0;
        }
    }
    sleep(1);
    //joining
    for(i = 0;i < pthreadNum; i++){
        pthread_join(pthreads[i], NULL);
    }

    free(pthreads);
    free(argsA);

    //keep loging
    printf("Scan finished.\n");
    return 0;
}
//扫描线程函数

void *scanThreadFunc(void *args)
{
    ScanArgsPtr temp;
    temp = (ScanArgsPtr) args;
    while (temp->port <= temp->end)
    {
        if (TCPportScanner(temp->ip,temp->port) && visited[temp->port] == 0){
            printf("----------port %5d -----------TCP Open\n",temp->port);
            visited[temp->port] = 1;
            }
        temp->port += temp->pNum;
    }
}
//tcp 端口扫描
int TCPportScanner(char *ip, int port)
{
    //socket 文件描述符，描述符状态，连接状态
    int sockfd,len,fcntlStatus,connectStatus;
    //socket 地址结构体
    struct sockaddr_in addr;
    //超时
    struct timeval timeout;
    //读写文件时的句柄
    fd_set fdr,fdw;

    //置空结构体
    memset(&addr, 0, sizeof(addr));
    memset(&timeout, 0, sizeof(timeout));

    //设置为IP通信
    addr.sin_family = AF_INET;
    //设置地址结构体中的IP地址
    addr.sin_addr.s_addr = inet_addr(ip);
    //设置地址结构体中的端口号
    addr.sin_port = htons(port);
    //创建socket 套接字
    if ((sockfd = socket(AF_INET, SOCK_STREAM,0)) < 0){
        return 0;
    }
    //设置套接字为非阻塞模式
    fcntlStatus = fcntl(sockfd, F_GETFL, 0);
    if (fcntlStatus < 0){
        close(sockfd);
        return 0;
    }
    fcntlStatus |= O_NONBLOCK;
    if (fcntl(sockfd, F_SETFL, fcntlStatus) < 0){
        close(sockfd);
        return 0;
    }
    //尝试连接
    connectStatus = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (connectStatus != 0){
        if (errno == EINPROGRESS){
            FD_ZERO(&fdr);
            FD_ZERO(&fdw);
            FD_SET(sockfd, &fdr);
            FD_SET(sockfd, &fdw);

            //设置1s超时
            timeout.tv_sec == 1;
            timeout.tv_usec = 0;
            connectStatus = select(sockfd + 1, &fdr, &fdw, NULL, &timeout);

            // if failed or timeout
            if (connectStatus <= 0 || connectStatus == 2){
                close(sockfd);
                return 0;
            }
            // if success
            if (connectStatus == 1 && FD_ISSET(sockfd, &fdw)) {
                close(sockfd);
                return 1;
            }
            close(sockfd);
            return 0;

        }
    }
}

