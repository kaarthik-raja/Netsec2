#include <bits/stdc++.h>
#include <stdio.h> 
#include <sys/time.h>
#include <netdb.h>
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <pthread.h> 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <bits/stdc++.h>
#include<sys/time.h>
using namespace std;
#define MAX 80 
#define SA struct sockaddr 
void func(int sockfd) 
{ 
    char buff[MAX]; 
    int n; 
    for (;;) { 
        bzero(buff, sizeof(buff)); 
        printf("Enter the string : "); 
        n = 0; 
        char ch=getchar();
        while (ch != '\n') 
        {
            buff[n]=ch;
            ch=getchar();n++;
        } 
        cout<<buff<<"\n";
        write(sockfd, buff, sizeof(buff)); 
        cout<<"Completed wrinting"<<"\n";
        bzero(buff, sizeof(buff)); 
        read(sockfd, buff, sizeof(buff)); 
        cout<<"From server:"<<endl;
        cout<<buff<<"\n";
        if ((strncmp(buff, "exit", 4)) == 0) { 
            printf("Client Exit...\n"); 
            break; 
        } 
        break;
    } 
} 
  
int main(int argc,char* argv[]) 
{ 
    int sockfd, connfd; 
    int port_num = atoi(argv[1]);
    struct sockaddr_in servaddr, cli; 
  
    // socket create and varification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else
    {
        printf("Socket successfully created..\n"); 
    }
    bzero(&servaddr, sizeof(servaddr)); 
  
    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = inet_addr("192.168.0.9"); 
    servaddr.sin_port = htons(port_num); 
  
    // connect the client socket to server socket 
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
        printf("connection with the server failed...\n"); 
        exit(0); 
    } 
    else
        printf("connected to the server..\n"); 
  
    // function for chat 
    func(sockfd); 
  
    // close the socket 
    close(sockfd); 
} 
