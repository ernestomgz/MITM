DEPS = inquisitor.c packetManage.c utils.c targets.c 
FLAGS = -lnet -lpcap -Wno-deprecated-declarations
DFLAGS=  -g -Wall -Werror

all: $(DEPS)
	clear
	gcc $(DEPS) -o inquisitor $(FLAGS)
	./inquisitor 172.18.0.3 02:42:ac:12:00:03 172.18.0.4 02:42:ac:12:00:04
d:
	clear
	gcc $(DEPS) -o inquisitor $(FLAGS) $(DFLAGS)
	./inquisitor 172.18.0.3 02:42:ac:12:00:03 172.18.0.4 02:42:ac:12:00:04
