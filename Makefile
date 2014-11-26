#
# Makefile for ICI-PROJECT2
#
# Author: Himanshu Mehra
# Email : hmehra@usc.edu
#


CC=gcc
CFLAGS=-g -Wall -Werror
LFLAGS=-lpcap
EXE= endhost router traffana 
LOGS=*.attackinfo *.log

all: $(EXE)

clean:
	rm -f $(EXE) $(LOGS)

endhost:
	$(CC) $(CFLAGS) endhost.c -o endhost

router:
	$(CC) $(CFLAGS) router.c -o router $(LFLAGS)


traffana:
	$(CC) $(CFLAGS) traffana.c -o traffana $(LFLAGS)

debug:
	$(CC) $(CFLAGS) -DDEBUG endhost.c -o endhost
	$(CC) $(CFLAGS) -DDEBUG router.c -o router $(LFLAGS)
	$(CC) $(CFLAGS) -DDEBUG traffana.c -o traffana $(LFLAGS)
