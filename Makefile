all:
	gcc main.c -o a.out -I/System/Volumes/Data/sgoinfre/goinfre/Perso/ernmarti/homebrew/Cellar/libnet/1.2/include -I/System/Volumes/Data/sgoinfre/goinfre/Perso/ernmarti/homebrew/opt/libpcap/include -v && ./a.out 
debug: Docker/
	gcc main.c -Wall -g -o a.out -I/System/Volumes/Data/sgoinfre/goinfre/Perso/ernmarti/homebrew/Cellar/libnet/1.2/include -I/System/Volumes/Data/sgoinfre/goinfre/Perso/ernmarti/homebrew/opt/libpcap/include -v  && ./a.out 
