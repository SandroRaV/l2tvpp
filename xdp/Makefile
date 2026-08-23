CLANG  ?= clang
CC     ?= gcc
CFLAGS ?= -O2 -Wall

all: l2tp_steer.bpf.o l2tp_steer

l2tp_steer.bpf.o: l2tp_steer.bpf.c
	$(CLANG) -O2 -g -Wall -target bpf -c $< -o $@

l2tp_steer: l2tp_steer.c
	$(CC) $(CFLAGS) $< -o $@ -lbpf

clean:
	rm -f l2tp_steer.bpf.o l2tp_steer

.PHONY: all clean
