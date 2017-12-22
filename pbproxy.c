/*
 * pbproxy.c
 *
 *  Created on: Nov 1, 2017
 *      Author: shalaka sidmul
 */
#include "serverProxy.h"
#include "clientProxy.h"
extern int optind;

unsigned char * getKeyFromFile(char *keyFileName);
int readArguments(int argc, char **argv);
struct sockaddr_in createListenSocketAddr(struct sockaddr_in proxy_addr);
struct sockaddr_in createDestinationSocketAddr(struct sockaddr_in destination_addr);
struct sockaddr_in createClientSocketAddr(struct sockaddr_in proxy_addr);
unsigned char * getKeyFromFile(char *keyFileName);


int listenOnPort;
char *destinationHost;
int destinationPort;
unsigned char *key;
int serverMode = 0;
struct hostent *host;

struct sockaddr_in createListenSocketAddr(struct sockaddr_in proxy_addr) {
	/* create sock_addr for listening */
	bzero(&proxy_addr, sizeof(proxy_addr));
	proxy_addr.sin_family = AF_INET;
	proxy_addr.sin_addr.s_addr = htons(INADDR_ANY);
	proxy_addr.sin_port = htons(listenOnPort);
	printf("proxy_addr.sin_port: %d", proxy_addr.sin_port);
	return proxy_addr;
}

struct sockaddr_in createDestinationSocketAddr(struct sockaddr_in destination_addr) {
	/* create sock_addr for connecting to destination*/
	bzero(&destination_addr, sizeof(destination_addr));
	destination_addr.sin_family = AF_INET;
	destination_addr.sin_addr.s_addr = ((struct in_addr *) (host->h_addr))->s_addr;
	destination_addr.sin_port = htons(destinationPort);
	printf("destination_addr.sin_port: %d", destination_addr.sin_port);
	return destination_addr;
}

struct sockaddr_in createClientSocketAddr(struct sockaddr_in proxy_addr){
	bzero(&proxy_addr, sizeof(proxy_addr));
	proxy_addr.sin_family = AF_INET;
	proxy_addr.sin_addr.s_addr = ((struct in_addr *)(host->h_addr))->s_addr;
	proxy_addr.sin_port = htons(destinationPort);
	return proxy_addr;
}

int main(int argc, char **argv){
	readArguments(argc,argv);
	host = gethostbyname(destinationHost);
	if(host == 0){
		printf("Invalid destination.");
		return 0;
	}
	if(serverMode == 1){
		/* create sock_addr for listening */
		struct sockaddr_in proxy_addr;
		proxy_addr = createListenSocketAddr(proxy_addr);
		/* create sock_addr for connecting to destination*/
		struct sockaddr_in destination_addr;
		destination_addr = createDestinationSocketAddr(destination_addr);
		serverSideProxy(key, proxy_addr, destination_addr);
	}else{
		/* create socket for client to connect to destination */
		struct sockaddr_in proxy_addr;
		//proxy_addr = createClientSocketAddr(proxy_addr);
		bzero(&proxy_addr, sizeof(proxy_addr));
		proxy_addr.sin_family = AF_INET;
		proxy_addr.sin_addr.s_addr = ((struct in_addr *)(host->h_addr))->s_addr;
		proxy_addr.sin_port = htons(destinationPort);
		clientSideProxy(key, proxy_addr);
	}
}

int readArguments(int argc, char **argv){
	int option;
	char *keyFileName;
	while ((option = getopt(argc, argv, "lk")) != -1) {
		switch (option) {
		case 'l':
			serverMode = 1;
			listenOnPort = (int)strtol(argv[optind], NULL, 10);
			break;
		case 'k':
			if(argv[optind] == NULL){
				printf("key file name must be specified.");
			}else{
				keyFileName = argv[optind];
				key = getKeyFromFile(keyFileName);
				if(key == NULL){
					printf("Invalid key.");
					return 0;
				}
				destinationHost = argv[optind + 1];
				destinationPort = (int)strtol(argv[optind + 2], NULL, 10);
			}
			break;
		default:
			printf("For server, run: ./pbproxy -l <server_port> -k <keyfile> localhost <ssh_port>\nFor client, run:ssh -o \"ProxyCommand ./pbproxy -k <keyfile> <server_name> <server_port>\" localhost");
			return 1;
		}

	}

}

unsigned char * getKeyFromFile(char *keyFileName){
	FILE *fp = fopen(keyFileName,"rb");
	unsigned char * key = NULL;
	int lengthOfKey;
	if(fp){
		fseek(fp,0,SEEK_END); /* take pointer to end of file */
		lengthOfKey = ftell(fp); /* get position of pointer */
		rewind(fp);
		key = (unsigned char * )malloc(lengthOfKey*(sizeof(char)));
		fread(key, 1, lengthOfKey,fp);
		fclose(fp);
	}else{
		fprintf(stderr, "Could not open file: %s", keyFileName);
	}
	return key;
}
