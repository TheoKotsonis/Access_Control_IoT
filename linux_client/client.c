#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>

#define BUFFERSIZE (1024)
#define MESSAGE "Hello.. I am the client"


int main(int argc, char **argv)
{
        int                  sockfd;            /* the socket file descriptor                                              */
        struct sockaddr_in6  remaddr;           /* structure that holds the remote address                                 */
        socklen_t            remaddrlen;        /* size of remaddr                                                         */
	socklen_t clilen;
        struct sockaddr_in6  client_addr;
        struct ifreq         ifr;               /* structure that holds information about the interface we're going to use */
        char                buffer[BUFFERSIZE];            /* buffer to store received data or data that will be send                 */
        size_t               buffersize;        /* stores the size of the buffer                                           */
        ssize_t              bytes;             /* stores how many bytes have been received or sent                        */
        char                *inval_char;        /* stores the first invalid character of the port, if there is one         */
        unsigned short       port;              /* stores the port as a number, not a string                               */
        char str[INET6_ADDRSTRLEN];
        
        /* check if number of arguments is correct */
        if (argc != 4) {
                printf("Usage: %s INTERFACE IP PORT\n", argv[0]);
                exit(EXIT_FAILURE);
        }
        
        inval_char = NULL;
        
        /* parse the port */
        port = (unsigned short)strtol(argv[3], &inval_char, 10);

        /* check if there were invalid characters in the port string */
        if (inval_char[0] != '\0') {  
                fprintf(stderr, "ERROR invalid port number\n");
                exit(EXIT_FAILURE);
        }
        
        printf("connecting to host %s on port %u, using interface %s...\n", argv[2], port, argv[1]);
        
        /* create the socket */
        sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        
        if (sockfd == -1) {
                fprintf(stderr, "ERROR socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP) FAILED: %s\n",
                                strerror(errno));
                exit(EXIT_FAILURE);
        }
        
        /* zero the ifr struct so there's no junk in it */
        memset(&ifr, 0, sizeof(ifr));
        
        /* copy the interface name into the ifr struct */
        strncpy(ifr.ifr_name, argv[1], IFNAMSIZ-1);
        
        /* call ioctl to fill the interface index */
        if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
                fprintf(stderr, "ERROR ioctl(sockfd, SIOCGIFINDEX, &ifr) FAILED: %s\n",
                                strerror(errno));
        }

        /* set the socket option that specifies the interface to use */
        if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) == -1) {
                fprintf(stderr, "ERROR setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, "
                                "(void *)&ifr, sizeof(ifr)) FAILED: %s\n",
                                strerror(errno));
                close(sockfd);
                exit(EXIT_FAILURE);
        }
        
        memset((char *)&remaddr, 0, sizeof(remaddr));
        
        remaddr.sin6_family = AF_INET6;
        remaddr.sin6_port   = htons(port);
        
        inet_pton(AF_INET6, argv[2], &remaddr.sin6_addr);
        
        remaddrlen = sizeof(remaddr);
         
        printf("Ready to send data..\n");
       
        /* now send a datagram */
	  if (sendto(sockfd, MESSAGE, sizeof(MESSAGE), 0, (struct sockaddr *)&remaddr, remaddrlen) < 0) {
	      perror("sendto failed");
	      exit(4);
	  }

	  printf("waiting for a reply...\n");
	  clilen = sizeof(client_addr);
	  if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&remaddr, &remaddrlen) < 0) {
	      perror("recvfrom failed");
	      exit(4);
	  }

	  printf("got '%s' from %s\n", buffer, inet_ntop(AF_INET6, &remaddr.sin6_addr, str, INET6_ADDRSTRLEN));
        
        close(sockfd);
        
        return 0;
}
