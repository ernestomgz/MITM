all:
	clear
	gcc inquisitor.c packetManage.c -o inquisitor -lnet -lpcap -Wno-deprecated-declarations
	./inquisitor 1.1.1.1 aa:aa:aa:aa:aa:aa 2.2.2.2 bb:bb:bb:bb:bb:bb

d:
	gcc inquisitor.c packetManage.c -o a.out -I/System/Volumes/Data/sgoinfre/goinfre/Perso/$USER/homebrew/Cellar/libnet/1.2/include -lpcap -v -Wall -g && ./a.out
