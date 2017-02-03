#computer-calisthenics

A collection of materials from posts on a blog I never published about learning windows dll injection techniques.

I wanted to learn more about process injection so I wrote some mediawiki pages about each thing I learned. When the imagetragick bug came around I rm'd the mediawiki vm that had the unpublished pages, forgetting that the pages are stored in a mysql db, not in the /var/www/ i tar'd up. Luckily, the accompanying materials for the pages were on a git repo on a different box. Dumping these here until I eventually have time to rewrite the pages.

Many of the referenced material and further-reading links were lost, but here are some from the programming challenge. A few of these are straight up copypasta, like the tcp echo server or the openssl base64, as the main goal was writing a self modifying elf in C:

https://stackoverflow.com/questions/9406840/rsa-encrypt-decrypt

https://stackoverflow.com/questions/4812869/how-to-write-self-modifying-code-in-x86-assembly

https://www.cs.cmu.edu/afs/cs/academic/class/15213-f99/www/class26/tcpclient.c

https://www.cs.cmu.edu/afs/cs/academic/class/15213-f99/www/class26/tcpserver.c

http://linux.die.net/man/2/mprotect

https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c - answer 5
