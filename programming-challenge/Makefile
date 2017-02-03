all: both

both: qsc overwrite
qsc: qsc.c
	gcc -o qsc qsc.c -lssl -lcrypto -g
overwrite: overwrite.c
	gcc -o overwrite overwrite.c -g
clean:
	rm qsc overwrite
