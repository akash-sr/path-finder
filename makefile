OBJS = trace_route.o pathfinder.o
PROGS =	trace_route pathfinder

CLEANFILES = core core.* *.core *.o temp.* *.out typescript* \

all:	${PROGS}

pathfinder:	pathfinder.c
		gcc pathfinder.c -o pathfinder
		
trace_route:	trace_route.c
		gcc trace_route.c -lpthread -o trace_route

clean:
		rm -f ${PROGS} ${CLEANFILES}
