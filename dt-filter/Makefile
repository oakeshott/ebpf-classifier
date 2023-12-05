######################################################################
# @author      : t-hara (t-hara@$HOSTNAME)
# @file        : Makefile
# @created     : Friday Oct 21, 2022 19:49:54 JST
######################################################################

IDIR =./include
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=obj

LIBS=

_OBJ = main.o 
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

# $(ODIR)/%.o: %.c
# 	$(CC) -c -o $@ $< $(CFLAGS)

main:
	# $(CC) -o $@ $^ $(CFLAGS) $(LIBS)
	cc -shared -fPIC $(CFLAGS) -o dt_filter.so dt_filter_rawsocket_us.c

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o

