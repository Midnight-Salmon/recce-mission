/* recce-mission.c */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include "banner.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define VERSION_MAJOR 0
#define VERSION_MINOR 1 

enum PortState {
	UNKNOWN,
	OPEN,
	CLOSED,
	FILTERED
};

struct ScanResult {
	char address[INET_ADDRSTRLEN];
	enum PortState ports[65536];
};

/* Scan a sequence of ports for one address. */
static struct ScanResult *scan_ports(
		char address[],
		int portc,
		unsigned short ports[]) {

	/* Build addrinfo for socket, resolving domain if required. */

	struct addrinfo hints;
	struct addrinfo *target_info;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (getaddrinfo(address, NULL, &hints, &target_info) != 0) {
		fprintf(stderr, "Error: could not resolve target %s\n", address);
		return NULL;
	}

	/* Prepare ScanResult with IP string. */

	struct ScanResult *result = malloc(sizeof(struct ScanResult));
	memset(&(result->ports), UNKNOWN, sizeof(enum PortState) * 65535);
	void *sock_addr;
	if (target_info->ai_family == AF_INET) {
		sock_addr = &(((struct sockaddr_in *)target_info->ai_addr)->sin_addr);
	}

	else {
		sock_addr = &(((struct sockaddr_in6 *)target_info->ai_addr)->sin6_addr);
	}

	inet_ntop(
			target_info->ai_family,
			sock_addr,
			result->address,
			sizeof(result->address));

	/* Scan port sequence.
	 * Build sockaddr manually to avoid multiple DNS queries.*/

	printf("Scanning %s (%s)\n", address, result->address);
	for (int i = 0; i < portc; i++) {
		if (target_info->ai_family == AF_INET) {
			((struct sockaddr_in *)target_info->ai_addr)
				->sin_port = htons(ports[i]);
		}

		else {
			((struct sockaddr_in6 *)target_info->ai_addr)
				->sin6_port = htons(ports[i]);
		}

		/* Init socket. 
	 	* Enable failing connection on ICMP error to detect filtered ports. */

		SOCKET scan_socket = socket(
				target_info->ai_family,
				target_info->ai_socktype,
				target_info->ai_protocol);

		if (scan_socket == INVALID_SOCKET) {
			fprintf(stderr, "Error: socket init failed.");
			freeaddrinfo(target_info);
			return NULL;
		}

		const char icmp = 1;
		setsockopt(
				scan_socket,
				IPPROTO_TCP,
				TCP_FAIL_CONNECT_ON_ICMP_ERROR,
				&icmp,
				sizeof(icmp));

		int r = connect(
				scan_socket,
				target_info->ai_addr,
				target_info->ai_addrlen);
		
		/* Determine state of port based on result of connection attempt. */
		
		if (r == 0) {
			result->ports[ports[i]] = OPEN;
		}

		else {

			switch (WSAGetLastError()) {

				/* Port is closed. */

				case WSAECONNREFUSED:
				result->ports[ports[i]] = CLOSED;
				break;

				/* Timed out or ICMP error, port is likely filtered. */

				case WSAETIMEDOUT:
				case WSAEHOSTUNREACH:
				result->ports[ports[i]] = FILTERED;
				break;
			}
		}

		closesocket(scan_socket);
	}

	freeaddrinfo(target_info);
	return result;
}

int main(int argc, char *argv[]) {

	/* Parse args. */

	enum { AUTO, INTERACTIVE } mode = AUTO;
	int option;
	while ((option = getopt(argc, argv, "i")) != -1) {
		switch (option) {
			case 'i':
				mode = INTERACTIVE;
				break;

			case '?':
				printf(HELPTEXT);
				exit(1);
				break;

			default:
				mode = AUTO;
				break;
		}
	}

	/* Init Windows sockets. */

	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
		fprintf(stderr, "Error: Winsock2 init failed.\n");
		exit(1);
	}

	if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion !=2)) {
		fprintf(stderr, "Error: Winsock v2.2 not available.\n");
		WSACleanup();
		exit(1);
	}

	/* Print banner with version number. */

	printf(BANNER, VERSION_MAJOR, VERSION_MINOR);

	/* TODO: Replace test code with user-selected mode. */
	
	unsigned short ports_to_scan[] = { 22, 80 };
	struct ScanResult *mrrp = scan_ports("scanme.nmap.org", 2, ports_to_scan);
	for (int i = 0; i < (sizeof(ports_to_scan) / sizeof(unsigned short)); i++) {
		printf("Port %d: %d\n", ports_to_scan[i], mrrp->ports[ports_to_scan[i]]);
	}

	free(mrrp);

	/* Clean up Windows sockets. */

	WSACleanup();
	return 0;
}
