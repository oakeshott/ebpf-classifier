######################################################################
# @author      : t-hara (t-hara@$HOSTNAME)
# @file        : Makefile
# @created     : Friday Oct 21, 2022 19:49:54 JST
######################################################################

IDIR =./include
CC=gcc
CFLAGS=-I$(IDIR) -I/usr/include/bcc -lbcc

ODIR=obj

LIBS=-L/usr/lib

_OBJ = main.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

# $(ODIR)/%.o: %.c
# 	$(CC) -c -o $@ $< $(CFLAGS)

main:
	# $(CC) -o $@ $^ $(CFLAGS) $(LIBS)
	# gcc -shared -fPIC $(CFLAGS) $(LIBS) -o filter.so filter_userspace.c -O3 -lpthread
	gcc -shared -fPIC $(CFLAGS) $(LIBS) -o filter.so filter_rawsocket_us.c -O3

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o

