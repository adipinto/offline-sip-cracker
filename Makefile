#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
#
CC = gcc
CFLAGS  = -Wall -g
OPTIMIZATION = -O3
OUTPUT = osc
FIX_LINKER_ERROR = -Wl,--no-as-needed # Fix linker errors in Ubuntu 11.10
LINKER = $(FIX_LINKER_ERROR) -lssl -lpcap

# typing 'make' will invoke the first target entry in the file 
#
all: osc

# Create the executable file osc (offline-sip-cracker)
#
osc:          md5.o main.o memory.o file.o globals.o pcap.o
		$(CC) $(CFLAGS) $(LINKER) $(OPTIMIZATION) -o $(OUTPUT) md5.o main.o memory.o file.o globals.o pcap.o

# Globals
#
globals.o:   globals.c globals.h
		$(CC) $(CFLAGS) -c globals.c

# Pcap
#
pcap.o:   pcap.c pcap.h
		$(CC) $(CFLAGS) -c pcap.c
		
# Main
#
main.o: main.c main.h
		$(CC) $(CFLAGS) -c main.c

# Md5
#
md5.o:   md5.c md5.h
		$(CC) $(CFLAGS) -c md5.c
		
# Memory
#
memory.o:   memory.c memory.h
		$(CC) $(CFLAGS) -c memory.c
		
# File
#
file.o:   file.c file.h
		$(CC) $(CFLAGS) -c file.c

# To start over from scratch, type 'make clean'.  This
# removes the executable file, as well as old .o object
# files and *~ backup files:
#
clean:
		rm -f $(OUTPUT) *.o *~
