A while back a company was looking for job applicants and presented a programming challenge. I decided to give the challenge a shot. There were two options in the challenge, one involving GUI, and one involving self modifying C. I chose the latter.

The challenge was to write an encrypted chat program that, upon execution, had to modify itself in order to function properly, or die.

Some googling and hilarious failure involving blowing it with a strncpy later, I had a working solution to the challenge.

Here is the meat of my solution.

> apt-get install libssl-dev
> openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096 && openssl rsa -pubout -in private_key.pem -out public_key.pem
>make qsc

send a message: ./qsc 1 "public_key.pem" 127.0.0.1 "message" 0
receive a message: ./qsc 0 "private_key.pem" 0