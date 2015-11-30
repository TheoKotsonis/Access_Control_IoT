#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "thread.h"
#include "hmac_sha256.h"

#define SERVER_MSG_QUEUE_SIZE   (8)
#define SERVER_BUFFER_SIZE      (64)

#define MESSAGE "Hi..."

static int server_socket = -1;
static char server_buffer[SERVER_BUFFER_SIZE];
static char server_stack[THREAD_STACKSIZE_DEFAULT];
static msg_t server_msg_queue[SERVER_MSG_QUEUE_SIZE];

void hmac_constructor(void)
{
    char *message = "Hi There";
    
    unsigned char mac[SHA256_DIGEST_LENGTH];
    char *key;
    char output[2 * SHA256_DIGEST_LENGTH + 1];
    int i;
    
    key = malloc(sizeof(key));
        if (key == NULL) {
            fprintf(stderr, "Can't allocate memory\n");
            return NULL;
        }

    strcpy( key, "1234");

    printf("HMAC-SHA256 Construction \n\n");

    hmac_sha256((unsigned char *)key, strlen(key), (unsigned char *) message, strlen(message), mac, SHA256_DIGEST_LENGTH);

    output[2 * SHA256_DIGEST_LENGTH] = '\0';

    for (i = 0; i < SHA256_DIGEST_LENGTH ; i++) {
       sprintf(output + 2*i, "%02x", mac[i]);
    }

    printf("H: %s\n", output);

    printf("Construction completed \n\n");
}

static void *_server_thread(void *args)
{
    struct sockaddr_in6 server_addr = in6addr_any;
    uint16_t port;
    char str[INET6_ADDRSTRLEN];
    msg_init_queue(server_msg_queue, SERVER_MSG_QUEUE_SIZE);
    server_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    /* parse port */
    port = (uint16_t)atoi((char *)args);
    if (port == 0) {
        printf("Error: invalid port specified\n");
        return NULL;
    }
    memset(&server_addr.sin6_addr, 0, sizeof(server_addr.sin6_addr));
    
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(port);
    if (server_socket < 0) {
        printf("error initializing socket\n");
        server_socket = 0;
        return NULL;
    }
    
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        server_socket = -1;
        printf("error binding socket\n");
        return NULL;
    }
    printf("Success: started UDP server on port %" PRIu16 "\n", port);
    
    while(1) {
	int res;
	struct sockaddr_in6 src;
	socklen_t src_len = sizeof(struct sockaddr_in6);

	if ((res = recvfrom(server_socket, server_buffer, sizeof(server_buffer), 0,
		            (struct sockaddr *)&src, &src_len)) < 0) {
	    printf("Error on receive\n");
	}
	else if (res == 0) {
	    printf("Peer did shut down\n");
	}
	else {
	    printf("Received data: %s \n",server_buffer);
	}

	printf("got '%s' from %s and port: %d\n", server_buffer,
	   inet_ntop(AF_INET6, &src.sin6_addr, str, INET6_ADDRSTRLEN),ntohs(src.sin6_port));
	src.sin6_port = htons(src.sin6_port);
	if (sendto(server_socket, MESSAGE, sizeof(MESSAGE), 0, (struct sockaddr *)&src, src_len) < 0) {
	    printf("could not send\n");
	}
	else {
	    printf("Success: send message to %s:%u\n", str, port);
	}
    }
    return NULL;
}

static int udp_start_server(char *port_str)
{
    // check if server is already running
    if (server_socket >= 0) {
        puts("Error: server already running");
        return 1;
    }
    // start server (which means registering pktdump for the chosen port)
    if (thread_create(server_stack, sizeof(server_stack), THREAD_PRIORITY_MAIN - 1,
                      CREATE_STACKTEST, _server_thread, port_str, "UDP server") <= KERNEL_PID_UNDEF) {
        server_socket = -1;
        puts("error initializing thread");
        return 1;
    }
    return 0;
}

int udp_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s [server]\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "server") == 0) {
        if (argc < 3) {
            printf("usage: %s server [start]\n", argv[0]);
            return 1;
        }
        if (strcmp(argv[2], "start") == 0) {
            if (argc < 4) {
                printf("usage %s server start <port>\n", argv[0]);
                return 1;
            }
            return udp_start_server(argv[3]);
        }
        else {
            puts("error: invalid command");
            return 1;
        }
    }
    else {
        puts("error: invalid command");
        return 1;
    }
}

/** @} */
