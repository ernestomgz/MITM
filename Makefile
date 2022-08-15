all:
	gcc main.c -o a.out -I/System/Volumes/Data/sgoinfre/goinfre/Perso/ernmarti/homebrew/Cellar/libnet/1.2/include -lpcap -v  && ./a.out 
debug: Docker/
	gcc main.c -o a.out -I/System/Volumes/Data/sgoinfre/goinfre/Perso/ernmarti/homebrew/Cellar/libnet/1.2/include -lpcap -v -Wall -g && ./a.out 
