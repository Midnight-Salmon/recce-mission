#!/bin/bash
gcc \
  recce-mission.c \
  -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic \
  -lws2_32 \
  -Wall -Wextra -std=c99 -pedantic -O2 \
  -pthread \
  -o reccem.exe
