OBJS = fastertraceroute.o findlongestcommonpath.o
PROGS =	fastertraceroute findlongestcommonpath

CLEANFILES = core core.* *.core *.o temp.* *.out typescript* \

all:	${PROGS}

findlongestcommonpath:	findlongestcommonpath.c
		gcc findlongestcommonpath.c -o findlongestcommonpath
		
fastertraceroute:	fastertraceroute.c
		gcc fastertraceroute.c -lpthread -o fastertraceroute

clean:
		rm -f ${PROGS} ${CLEANFILES}
