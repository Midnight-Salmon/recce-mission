/* recce-mission.c */

/* Copyright (C) 2025 Midnight Salmon.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 3 as published by
 * the Free Software Foundation.
 *
 * This program is distributed without any warranty; without even the implied
 * warranty of merchantability or fitness for a particular purpose. See the GNU
 * General Public License for more details. 
 *
 * Contact: mail@midnightsalmon.boo */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include "banner.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#define VERSION_MAJOR 1
#define VERSION_MINOR 1 
#define MAX_PORTS_COUNT 65536
#define MAX_THREADS 64

enum PortState {
  OPEN,
  FILTERED,
  CLOSED,
  UNKNOWN
};

struct ScanResult {
  char address[INET6_ADDRSTRLEN];
  enum PortState ports[MAX_PORTS_COUNT];
};

struct ScanThreadArgs {
  struct addrinfo *target_info;
  unsigned short port;
  enum PortState *destination;
};

/* ----------------------------------------------------------------------------
 * Print formatted scan result to file. */
static void print_scan_result(
  struct ScanResult *result,
  FILE *f,
  enum PortState log) {

  int heading = fprintf(f, "PORT SCAN RESULTS: %s\n", result->address);
  for (int i = 0; i < heading - 1; i++) {
    fprintf(f, "-");
  }

  fprintf(f, "\n");
  char *port_states[] = {"Open", "Filtered", "Closed", "?"};
  for (int i = 0; i < MAX_PORTS_COUNT; i++) {
    if (result->ports[i] <= log) {
      fprintf(f, "Port %-5d: %s\n", i, port_states[result->ports[i]]);
    }
  }
}

/* ----------------------------------------------------------------------------
 * Write port scan result to a txt file.
 * Filename is based on date and time. */
static int dump_scan_result(struct ScanResult *result) {

  /* Build filename from current date and time. */

  time_t current_time = time(NULL);
  struct tm *local_time = localtime(&current_time);
  char filename[22] = {0};
  strftime(filename, 22, "rm-%Y%m%d%H%M%S.txt", local_time);

  /* Write results to file. */

  FILE *f = fopen(filename, "w");
  if (f == NULL) {
    fprintf(stderr, "Error: could not open file for write.\n");
    return -1;
  }

  print_scan_result(result, f, UNKNOWN);
  if (fclose(f) != 0) {
    fprintf(stderr, "Error: write failed.\n");
    return -1;
  }

  return 0;
}

/* ----------------------------------------------------------------------------
 * Scan a single port. */
static void *scan_port(void *a) {
  struct ScanThreadArgs *args = (struct ScanThreadArgs *)a;
  struct addrinfo *target_info = args->target_info;
  unsigned short port = args->port;
  enum PortState *destination = args->destination;

  /* Copy sockaddr, cast to IPV4 format to set port. */

  struct sockaddr new_addr = *(target_info->ai_addr);
  struct sockaddr_in *new_addr_v4 = (struct sockaddr_in *)&new_addr;
  new_addr_v4->sin_port = htons(port);

  /* Init socket.
   * Enable failing connection on ICMP error to detect filtered ports. */

  SOCKET scan_socket = socket(
    target_info->ai_family,
    target_info->ai_socktype,
    target_info->ai_protocol);

  if (scan_socket == INVALID_SOCKET) {
    fprintf(
      stderr,
      "Error: could not create socket while scanning port %d.\n",
      port);

    pthread_exit(NULL);
  }

  const char icmp = 1;
  setsockopt(
    scan_socket,
    IPPROTO_TCP,
    TCP_FAIL_CONNECT_ON_ICMP_ERROR,
    &icmp,
    sizeof(icmp));

  /* Attempt connection. */

  int r = connect(scan_socket, &new_addr, sizeof(new_addr));

  /* Determine state of port based on result of connection attempt. */

  enum PortState state = UNKNOWN;
  if (r == 0) {
    state = OPEN;
  }

  else {

    switch (WSAGetLastError()) {

      /* Port is closed. */

      case WSAECONNREFUSED:
        state = CLOSED;
        break;

      /* Timed out or ICMP error, port is likely filtered. */

      case WSAETIMEDOUT:
      case WSAEHOSTUNREACH:
        state = FILTERED;
        break;

      default:
        state = UNKNOWN;
        break;
    }
  }

  closesocket(scan_socket);
  *destination = state;
  return NULL;
}

/* ----------------------------------------------------------------------------
 * Scan a sequence of ports for one address. */
static struct ScanResult *scan_ports(
  char *address,
  int portc,
  unsigned short *ports) {

  /* Build addrinfo for socket, resolving domain if required. */

  struct addrinfo hints;
  struct addrinfo *target_info = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  if (getaddrinfo(address, NULL, &hints, &target_info) != 0) {
    fprintf(stderr, "Error: could not resolve target %s.\n", address);
    return NULL;
  }

  /* Prepare ScanResult with IP string. */

  struct ScanResult *result = malloc(sizeof(struct ScanResult));
  memset(&(result->ports), UNKNOWN, sizeof(enum PortState) * MAX_PORTS_COUNT);
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

  /* Scan port sequence in chunks of MAX_THREADS followed by remainder. */
  /* Not the fastest method but probably the most simple. */

  struct ScanThreadArgs thread_args[portc];
  pthread_t threads[MAX_THREADS];
  for (int i = 0; i < portc; i++) {
    thread_args[i] = (struct ScanThreadArgs){
      target_info,
      ports[i],
      &(result->ports[ports[i]])};
  }

  int ports_index = 0;
  int chunks = portc / MAX_THREADS;
  int remainder = portc % MAX_THREADS;
  for (int c = 0; c < chunks; c++) {
    for (int i = 0; i < MAX_THREADS; i++) {
      pthread_create(
        &threads[i],
        NULL,
        &scan_port,
        (void *)&thread_args[ports_index]);

      ports_index++;
    }

    for (int i = 0; i < MAX_THREADS; i++) {
      pthread_join(threads[i], NULL);
    }
  }

  for (int i = 0; i < remainder; i++) {
    pthread_create(
      &threads[i],
      NULL,
      &scan_port,
      (void *)&thread_args[ports_index + i]);
  }

  for (int i = 0; i < MAX_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }

  freeaddrinfo(target_info);
  return result;
}

/* ----------------------------------------------------------------------------
 * Parse string of ports and port ranges. */
static int parse_port_list(char *list, unsigned short *ports) {
  int ports_added = 0;
  char *token = strtok(list, " ");
  while (token != NULL) {
    unsigned int x = MAX_PORTS_COUNT;
    unsigned int y = MAX_PORTS_COUNT;
    int bytes_x = 0;
    int bytes_y = 0;
    int matches = sscanf(token, "%u%n-%u%n", &x, &bytes_x, &y, &bytes_y);
    if (
      matches == 1
      && x < MAX_PORTS_COUNT
      && (size_t)bytes_x == strlen(token)) {

      ports[ports_added] = (unsigned short)x;
      ports_added++;
    }

    else if (
      matches == 2
      && x < MAX_PORTS_COUNT
      && y < MAX_PORTS_COUNT
      && x < y
      && (size_t)bytes_y == strlen(token)) {
      
      for (unsigned int i = x; i <= y; i++) {
        ports[ports_added] = (unsigned short)i;
        ports_added++;
      }
    }

    else {
      return -1;
    }

    token = strtok(NULL, " ");
  }

  return ports_added;
}

/* ----------------------------------------------------------------------------
 * Get scan parameters interactively.
 * Here be horrible nesting, yarr! */
static void interactive_mode(void) {
  int must_quit = 0;
  char line_buf[1024] = {0};
  struct ScanResult *prev_result = NULL;
  while (!must_quit) {
    printf(
      "\nInteractive mode:\n"
      "    [1] New scan\n"
      "    [2] Show scan results\n"
      "    [3] Dump scan results to disk\n"
      "    [4] Quit\n"
        );

    unsigned long option = 0;
    int valid_option = 0;
    char *end = NULL;
    while (!valid_option) {
      printf("~> ");
      fgets(line_buf, 1024, stdin);
      option = strtoul(line_buf, &end, 10);
      if (option >= 1 && option <= 4 && end != line_buf && *end == '\n') {
        valid_option = 1;
      }

      else {
        printf("Invalid selection.\n");
      }
    }

    switch (option) {
      case 1:

        /* New scan. */

        free(prev_result);
        char target[INET6_ADDRSTRLEN + 1];
        char port_list[1024];
        unsigned short ports[MAX_PORTS_COUNT];

        /* Get scan target. */

        printf("\nEnter target IP address or hostname.\n~> ");
        fgets(target, INET6_ADDRSTRLEN + 1, stdin);
        target[strcspn(target, "\n")] = 0;

        /* Get ports to scan. */

        printf("\nEnter individual ports or port ranges "
          "to scan, separated by spaces.\n");

        int have_ports = 0;
        int ports_added = 0;
        while (!have_ports) {
          printf("~> ");
          fgets(port_list, 1024, stdin);
          port_list[strcspn(port_list, "\n")] = 0;
          ports_added = parse_port_list(port_list, ports);
          if (ports_added > 0) {
            have_ports = 1;
          }

          else {
            printf("Invalid selection.\n");
          }
        }

        /* Scan. */

        printf("\nScanning %s...\n", target);
        prev_result = scan_ports(target, ports_added, ports);
        printf("Scan complete.\n");
        break;

      case 2:
        
        /* Print results of previous scan. */

        if (prev_result != NULL) {
          printf("\n");
          print_scan_result(prev_result, stdout, FILTERED);
        }

        else {
          printf("No scan results! Run a new scan.\n");
        }

        break;

      case 3:

        /* Dump results of previous scan to txt file. */

        if (prev_result != NULL) {
          dump_scan_result(prev_result);
          printf("Scan result dumped.\n");
        }

        else {
          printf("No scan results! Run a new scan.\n");
        }

        break;

      case 4:

        /* Quit. */

        must_quit = 1;
        break;
    }
  }
}

/* ----------------------------------------------------------------------------
 * Scan using command line arguments. */
static void args_mode(char *target, int portc, unsigned short *ports) {
  printf("Scanning %s...\n\n", target);
  struct ScanResult *result = scan_ports(target, portc, ports);
  print_scan_result(result, stdout, FILTERED);
}

/* ----------------------------------------------------------------------------
 * Program entry point. */
int main(int argc, char **argv) {

  /* Parse args. */

  enum {AUTO, INTERACTIVE, ARGS} mode = AUTO;
  int option = 0;
  char cmdline_target[INET6_ADDRSTRLEN + 1] = {0};
  unsigned short cmdline_ports[MAX_PORTS_COUNT] = {0};
  int cmdline_ports_num = 0;
  int have_cmdline_target = 0;
  while ((option = getopt(argc, argv, "it:p:")) != -1) {
    switch (option) {
      case 'i':
        mode = INTERACTIVE;
        break;

      case 't':
        mode = ARGS;
        if (optarg[0] != 0) {
          have_cmdline_target = 1;
          strncpy(cmdline_target, optarg, INET6_ADDRSTRLEN);
        }

        break;

      case 'p':
        mode = ARGS;
        cmdline_ports_num = parse_port_list(optarg, cmdline_ports);
        break;

      default:
        printf(HELPTEXT);
        exit(1);
        break;
    }
  }

  /* Init Windows sockets. */

  WSADATA wsa_data;
  if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
    fprintf(stderr, "Error: Winsock2 init failed.\n");
    exit(EXIT_FAILURE);
  }

  if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion !=2)) {
    fprintf(stderr, "Error: Winsock v2.2 not available.\n");
    WSACleanup();
    exit(EXIT_FAILURE);
  }

  /* Run user-selected mode. */

  switch (mode) {
    case INTERACTIVE:
      printf(BANNER, VERSION_MAJOR, VERSION_MINOR);
      interactive_mode();
      break;

    case ARGS:
      if (cmdline_ports_num > 0 && have_cmdline_target) {
        args_mode(cmdline_target, cmdline_ports_num, cmdline_ports);
      }

      else {
        printf(HELPTEXT);
      }

      break;

    default:
      printf(HELPTEXT);
      break;
  }

  /* Clean up Windows sockets. */

  WSACleanup();
  return 0;
}
