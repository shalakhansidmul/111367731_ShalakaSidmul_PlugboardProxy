/*
 * serverProxy.h
 *
 *  Created on: Nov 1, 2017
 *  Author: shalaka sidmul
 *  References:
 *  	1. https://tools.ietf.org/html/rfc3686#section-3.1
 *  	2. https://vcansimplify.wordpress.com/2013/03/14/c-socket-tutorial-echo-server/
 *		3. https://stackoverflow.com/questions/38255433/parameter-details-of-openssls-aes-ctr128-encrypt
 *		4. http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
 *		5. http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
 */
#ifndef SERVER_H
#define SERVER_H
#include<stdio.h>
#include<stdlib.h>
#include<getopt.h>
#include<openssl/aes.h>
#include<openssl/rand.h>
#include<netdb.h>
#include<strings.h>
#include<netinet/in.h>
#include <arpa/inet.h>
#include<pthread.h>
#include<sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#define BUFFER_SIZE 4096
#define IV_SIZE 8 /* size of IV is 8 octets */
#endif

struct relayData {
	unsigned char data[BUFFER_SIZE];
	unsigned char initVector[IV_SIZE];
};

struct counterState{
	unsigned char ivec[AES_BLOCK_SIZE]; /* the initialization vector */
	unsigned int num;
	unsigned char ecount[AES_BLOCK_SIZE];
};

struct clientThreadArgs{
	int clientSockFd;
	unsigned char * key;
	struct sockaddr_in 	destination_sockAddr;
};

void initializeCounterState(struct counterState *state, const unsigned char iv[IV_SIZE]){
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);
	memset(state->ivec + 8, 0, 8); /*set last 8 bytes of initialization vector to 0*/
	memcpy(state->ivec, iv, 8); /* copy initialization vector from client into first 8 bytes of counter_state->ivec */
}

/* decrypt and relay client's data to SSH server
 * encrypt and relay response of ssh server to client
 * */
void * clientRequestProcessor(void *args){

	int terminate;
	int bytesRead;
	int bytesWritten = 0;
	struct clientThreadArgs *clientArgs = (struct clientThreadArgs *)args;
	int clientSocketFd = clientArgs->clientSockFd;
	AES_KEY encrKey;
	int flags = -1;
	unsigned char buff[BUFFER_SIZE];
	struct relayData dataFromClient;
	struct relayData responseToClient;
	struct counterState csRcv;
	struct counterState csSend;
	/*connect to destination server*/
	int sshSockFd = socket(AF_INET,SOCK_STREAM,0);
	if (connect(sshSockFd, (struct sockaddr *)&clientArgs->destination_sockAddr, sizeof(clientArgs->destination_sockAddr)) != 0){
		fprintf(stderr,"Error connecting to destination server.");
		exit(0);
	}

	flags = fcntl(sshSockFd, F_GETFL);
	if(flags == -1){
		fprintf(stderr,"Error in  reading flags of destination server socket.Exiting..");
		close(sshSockFd);
		pthread_exit(NULL);
	}
	fcntl(sshSockFd, F_SETFL, flags | O_NONBLOCK);

	flags = fcntl(clientSocketFd, F_GETFL);
	if(flags == -1){
		fprintf(stderr,"Error in  reading flags of client socket. Exiting..");
		close(clientSocketFd);
		pthread_exit(NULL);
	}
	fcntl(clientSocketFd, F_SETFL, flags | O_NONBLOCK);

	bzero(buff, BUFFER_SIZE);
	if (AES_set_encrypt_key(clientArgs->key, 128, &encrKey) < 0) {
		fprintf(stderr, "Error while setting encryption key. Exiting...\n");
		pthread_exit(NULL);
	}

	while(1){
		/* read data from client */
		while((bytesRead = read(clientSocketFd, buff, BUFFER_SIZE)) >= 0){
			if(bytesRead == 0){
				close(clientSocketFd);
				close(sshSockFd);
				fprintf(stderr, "\n Exiting child thread for client.\n");
				pthread_exit(NULL);
			}
			if(bytesRead > 0){
				/* get IV sent by Client*/
				memcpy(dataFromClient.initVector, buff, IV_SIZE);
				initializeCounterState(&csRcv, dataFromClient.initVector);
				/*decrypt message from  client*/
				AES_ctr128_encrypt(buff + IV_SIZE, dataFromClient.data , bytesRead - IV_SIZE, &encrKey, csRcv.ivec, csRcv.ecount, &csRcv.num);
				/* send to decrypted data to sshd server */
				write(sshSockFd, dataFromClient.data, bytesRead - IV_SIZE);
			}
			if(bytesRead < BUFFER_SIZE){
				break;
			}
		}
		bytesWritten = 0;
		/*read reply from ssh server and relay it to client */
		while((bytesRead = read(sshSockFd, buff , BUFFER_SIZE)) >=0){
			if(bytesRead == 0){
				close(clientSocketFd);
				close(sshSockFd);
				fprintf(stderr, "\nServer done sending data to client. Exiting child thread for client. \n");
				pthread_exit(NULL);
			}
			if(bytesRead > 0){
				if(bytesRead > 0){
					/* Gnerate Random IV */
					if(!RAND_bytes(responseToClient.initVector, IV_SIZE)){
						fprintf(stderr, "Error in generating IV.");
					}

					unsigned char cipherText[bytesRead];
					initializeCounterState(&csSend,responseToClient.initVector);
					AES_ctr128_encrypt(buff, cipherText, bytesRead, &encrKey, csSend.ivec, csSend.ecount, &csSend.num);
					/*construct message to send */
					char * messageToClient = (char *)malloc(bytesRead + IV_SIZE);
					memcpy(messageToClient, responseToClient.initVector, IV_SIZE);
					memcpy(messageToClient + IV_SIZE, cipherText, bytesRead);
					bytesWritten = write(clientSocketFd, messageToClient, IV_SIZE + bytesRead);
					/*clean up temporary message*/
					free(messageToClient);
				}
			}
			if(bytesRead < BUFFER_SIZE){
				break;
			}
		}
	}
	/*cleanup*/
	close(clientSocketFd);
	close(sshSockFd);
	pthread_exit(0);
}


void serverSideProxy(unsigned char *key, struct sockaddr_in proxy_addr, struct sockaddr_in destination_addr){
	int proxySockFd;
	pthread_t clientRequestProcessorThread;
	/*create socket for listening to client connections */
	if ((proxySockFd = socket(AF_INET,SOCK_STREAM, 0)) < 0){
		fprintf(stderr, "Could not open socket for proxy. Exiting...");
		return;
	}
	/* bind the socket to port in the socket address for proxy */
	if( bind(proxySockFd, (struct sockaddr *) &proxy_addr, sizeof(proxy_addr)) < 0){
		fprintf(stderr, "Could not bind socket to port %d for proxy. Exiting...", proxy_addr.sin_port);
		return;
	}
	/* listen for client connections with backlog as 10 */
	listen(proxySockFd,10);
	do{
		struct sockaddr_in newClient;
		socklen_t length ;
		struct clientThreadArgs * newClientThreadArgs;
		length = sizeof(newClient);
		int newClientSockFd = -1;

		/* accept a client connection.
		 * create a child thread to process client's requests.
		 */
		if( (newClientSockFd = accept(proxySockFd, (struct sockaddr *)&newClient, &length)) <0){
			fprintf(stderr, "\nCould not accept client's connection.\n");
		}else{
			char clientIpAddr[INET_ADDRSTRLEN];
			inet_ntop( AF_INET, &newClient.sin_addr, clientIpAddr, INET_ADDRSTRLEN );
			fprintf(stderr, "\n Accepted connection request from  client at: %s\n", clientIpAddr);
			newClientThreadArgs = (struct clientThreadArgs *) malloc(sizeof(struct clientThreadArgs));
			newClientThreadArgs->clientSockFd = newClientSockFd;
			newClientThreadArgs->key = key;
			newClientThreadArgs->destination_sockAddr = destination_addr;
			/* create thread for processing client requests */
			pthread_create(&clientRequestProcessorThread, NULL, clientRequestProcessor, (void *)newClientThreadArgs );
			/*detach client processor thread for independent processing*/
			pthread_detach(clientRequestProcessorThread);
		}
	}while(1);

}
