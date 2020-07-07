src = fuzzer.c ptrace_helpers.c snapshot.c 
obj = $(src:.c=.o)

LDFLAGS = 

dragonfly: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(obj) dragonfly
