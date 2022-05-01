all:
	gcc -o pathfinder pathfinder.c -lpthread
clean:
	rm -rf pathfinder
