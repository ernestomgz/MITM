DEPS = inquisitor.c packetManage.c utils.c targets.c 
FLAGS = -lnet -lpcap -Wno-deprecated-declarations
DFLAGS=  -g -Wall -Werror

all: $(DEPS)
	clear
	gcc $(DEPS) -o inquisitor $(FLAGS)
	./inquisitor 1.1.1.1 aa:aa:aa:aa:aa:aa 2.2.2.2 bb:bb:bb:bb:bb:bb
d:
	clear
	
	gcc $(DEPS) -o inquisitor $(FLAGS) $(DFLAGS)
	./inquisitor 1.1.1.1 aa:aa:aa:aa:aa:aa 2.2.2.2 bb:bb:bb:bb:bb:bb
