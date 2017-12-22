go: pbproxy.c
	 gcc -g -o pbproxy pbproxy.c -lssl -lpthread -lcrypto
clean:
	rm pbproxy
