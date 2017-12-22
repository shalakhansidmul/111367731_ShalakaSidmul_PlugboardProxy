/**
 * clientProxy.h
 *
 * Created on: Nov 5, 2017
 * Author: Shalaka Sidmul
 * References :
 * 	1. https://stackoverflow.com/questions/15042470/redefinition-of-struct-error-i-only-defined-it-once
 */

#ifndef CLIENT_H
#define CLIENT_H
#include<signal.h>
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
#include<sys/types.h>
#include<string.h>
#include<errno.h>
#include<unistd.h>
#include<fcntl.h>
#endif

struct message {
	unsigned char data[BUFFER_SIZE];
	unsigned char initVector[IV_SIZE];
};

struct clientCounterState{
	unsigned char ivec[AES_BLOCK_SIZE]; /* the initialization vector */
	unsigned int num;
	unsigned char ecount[AES_BLOCK_SIZE];
};

void initializeClientCounterState(struct clientCounterState *state, const unsigned char iv[IV_SIZE]){
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);
	memset(state->ivec + 8, 0, 8); /*set last 8 bytes of initialization vector to 0*/
	memcpy(state->ivec, iv, 8); /* copy initialization vector from client into first 8 bytes of counter_state->ivec */
}

void signalHandler(int sig);
struct sockaddr_in serverSockAddr;
AES_KEY encDecrKey;

void signalHandler(int sig){
	signal(sig, SIG_IGN);
	printf("terminating SSH session.");
	exit(0);
}

int connectToServer(){
	int destinationSocketFd = socket(AF_INET,SOCK_STREAM,0);
	if (connect(destinationSocketFd, (struct sockaddr *)&serverSockAddr, sizeof(serverSockAddr)) < 0){
		exit(0);
	}
	return destinationSocketFd;
}

void clientSideProxy(unsigned char *key, struct sockaddr_in proxy_addr){
	int destSockFd;
	struct message commandToSend;
	struct message responseFromServer;
	int lengthOfData;
	struct clientCounterState csSend;
	struct clientCounterState csRcv;
	serverSockAddr = proxy_addr;
	destSockFd = connectToServer();
	int bytesRead;
	unsigned char randomBytes[IV_SIZE];
	/* initialize file descriptor for STDIN */
	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	/*check flags of serverSocket file descriptor*/
	if(fcntl(destSockFd, F_GETFL) == -1){
		close(destSockFd);
	}else{
		fcntl(destSockFd, F_SETFL, O_NONBLOCK );
	}

	AES_set_encrypt_key(key, 128, &encDecrKey);

	/* initialize buffer for command to send to server */
	bzero(commandToSend.data, BUFFER_SIZE);
	while(1){
		/*read from console: stdin*/
		while((bytesRead = read(STDIN_FILENO, commandToSend.data, BUFFER_SIZE)) >= 0){
			if(bytesRead == 0){
				fprintf(stderr, "Exiting.");
				exit(0);
			}

			if(bytesRead > 0){
				/* Gnerate Random IV */
				if(!RAND_bytes(commandToSend.initVector, IV_SIZE)){
					fprintf(stderr, "Error in generating IV.");
				}
				unsigned char cipherText[bytesRead];
				initializeClientCounterState(&csSend,commandToSend.initVector);
				AES_ctr128_encrypt(commandToSend.data, cipherText, bytesRead, &encDecrKey, csSend.ivec, csSend.ecount, &csSend.num);
				/*construct message to send */
				char * messageToServer = (char *)malloc(bytesRead + IV_SIZE);
				memcpy(messageToServer, commandToSend.initVector, IV_SIZE);
				memcpy(messageToServer + IV_SIZE, cipherText, bytesRead);
				/*write message to socket*/
				write(destSockFd, messageToServer, IV_SIZE + bytesRead);
				/*clean up temporary message*/
				free(messageToServer);
			}

			/*check if this was last message*/
			if(bytesRead < BUFFER_SIZE){
				break;
			}

		}
		/*read response of server*/
		unsigned char responseBuff[BUFFER_SIZE];
		int bytesWritten = 0;
		while((bytesRead = read(destSockFd, responseBuff, BUFFER_SIZE)) > 0){
			if(bytesRead == 0){
				fprintf(stderr, "Exiting");
				return;
			}

			if(bytesRead > 0){
				/*get the IV sent by server*/
				memcpy(responseFromServer.initVector, responseBuff, IV_SIZE);
				initializeClientCounterState(&csRcv, responseFromServer.initVector);
				/*decrypt message from  server*/
				unsigned char resp[bytesRead - IV_SIZE];
				AES_ctr128_encrypt(responseBuff + IV_SIZE, resp , bytesRead - IV_SIZE, &encDecrKey, csRcv.ivec, csRcv.ecount, &csRcv.num);
				/* Display data on console*/

				while(bytesWritten < bytesRead - IV_SIZE){
					bytesWritten += write(STDOUT_FILENO, resp + bytesWritten , bytesRead - IV_SIZE - bytesWritten);
				}
				bytesWritten = 0;
			}

			/*check if this was last message*/
			if(bytesRead < BUFFER_SIZE){
				break;
			}
		}

	}
}
