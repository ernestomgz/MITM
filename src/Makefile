all:
	clear
	gcc inquisitor.c packetManage.c utils.c targets.c -o inquisitor -lnet -lpcap -Wno-deprecated-declarations
	./inquisitor 1.1.1.1 aa:aa:aa:aa:aa:aa 2.2.2.2 bb:bb:bb:bb:bb:bb
d:
	clear
	gcc inquisitor.c packetManage.c utils.c targets.c -o inquisitor -lnet -lpcap -Wno-deprecated-declarations -g
	./inquisitor 1.1.1.1 aa:aa:aa:aa:aa:aa 2.2.2.2 bb:bb:bb:bb:bb:bb
