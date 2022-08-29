all:
	clear
	gcc inquisitor.c packetManage.c utils.c targets.c -o inquisitor -lnet -lpcap -Wno-deprecated-declarations
	./inquisitor 172.18.0.3 02:42:AC:12:00:03 172.18.0.4 02:42:ac:12:00:04
d:
	clear
	gcc inquisitor.c packetManage.c utils.c targets.c -o inquisitor -lnet -lpcap -Wno-deprecated-declarations -g
	./inquisitor 172.18.0.2 02:42:AC:12:00:02 172.18.0.3 02:42:ac:12:00:03
