#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#define BUFSIZE 4096

//int padding = RSA_PKCS1_PADDING;
int padding = RSA_PKCS1_OAEP_PADDING;

// this function is hardcoded to return 0, but the program will only run if it returns 1
unsigned int goAhead(void) {
    return(0);
}

// this function uses the approach from overwrite.c to overwrite goAhead with shellcode that returns 1
unsigned int overwrite_goAhead(void){
    unsigned int pgsz;
    unsigned char *ptr;
    unsigned int offset;
    printf("%s\n","in overwrite_goAhead here");

    pgsz = getpagesize();
    offset = ( unsigned int )( ( ( long ) goAhead ) & ( pgsz - 1 ) );
    ptr = ( unsigned char * ) ( ( long ) goAhead & ( ~ ( pgsz - 1 ) ) );

    if ( mprotect( ptr, pgsz, PROT_READ|PROT_EXEC|PROT_WRITE ) ) {
            printf("mprotect fail");
            return(1);
    }


    ptr[offset+0]=0x90;//weeeeee
    ptr[offset+1]=0x90;//eeeeeee
    ptr[offset+2]=0x90;//eeeeeee
    ptr[offset+3]=0x90;//eeeeeee

    ptr[offset+4]=0xb8;//ret 1
    ptr[offset+5]=0x31;
    ptr[offset+6]=0x00;
    ptr[offset+7]=0x00;
    ptr[offset+8]=0x00;
    ptr[offset+9]=0xc3;

}

RSA * createRSAWithFilename(unsigned char *filename,int public)
{
    printf("int public: %d\n", public);
    printf("file_name reference on line %d = %p\n", __LINE__, filename);
    FILE * fp;
    printf("filehandle declared\n");
    printf("filename: %s\n",filename);
    printf("i am right before the fopening\n");
    fp = fopen(filename,"r");// WHY! WHY DO YOU SEGFAULT?!
// lol right here used to be this huge comment block of pasted gdb output of this program
//  segfaulting when i try to use a private key.
//  I went on and on assuming it was somehow due to the overwriting of an unrelated function
//  turns out it was because i was strncpying the base64 decoded ciphertext buffer to another
//  before decrypting it, instead of just passing a pointer to the buffer I already had.
//  classic.
    if (fp == NULL){
        printf("fp is apparently somehow null\n");
        exit(1);
    }
    printf("keyfile opened\n");
    if(fp == NULL)
    {
        printf("Unable to open file: %s\n",filename);
        exit(1);   
    }
    printf("keyfile opened successfully\n");
    RSA *rsa= RSA_new();
    if(public)
    {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
        //rsa = PEM_read_RSAPublicKey(fp, $rsa, NULL, NULL);
        printf("public key rsa container created\n");
    }
    else
    {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
        printf("private key rsa container created\n");
    }
    if (!rsa) {
        printf("key fail\n");
        exit(1);
    }
    printf("leaving key maker\n");
    return rsa;
}

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    printf("file_name reference on line %d = %p\n", __LINE__, key);
    printf("in public encrypt\n");
    RSA * rsa = createRSAWithFilename(key,1);
    printf("successfully created key\n");
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    printf("attempted encrypting\n");
    return result;
}

int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{

    printf("in decrypt\n");
    printf("file_name reference on line %d = %p\n", __LINE__, key);
    RSA * rsa = createRSAWithFilename(key,0);
    printf("made key\n");
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

// heres some copypasta base64 functions, lol
char *base64encode (const void *b64_encode_this, int encode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    BUF_MEM *mem_bio_mem_ptr;    //Pointer to a "memory BIO" structure holding our base64 data.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                           //Initialize our memory sink BIO.
    BIO_push(b64_bio, mem_bio);            //Link the BIOs by creating a filter-sink BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);  //No newlines every 64 characters or less.
    BIO_write(b64_bio, b64_encode_this, encode_this_many_bytes); //Records base64 encoded data.
    BIO_flush(b64_bio);   //Flush data.  Necessary for b64 encoding, because of pad characters.
    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);  //Store address of mem_bio's memory structure.
    BIO_set_close(mem_bio, BIO_NOCLOSE);   //Permit access to mem_ptr after BIOs are destroyed.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);   //Makes space for end null.
    (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';  //Adds null-terminator to tail.
    return (*mem_bio_mem_ptr).data; //Returns base-64 encoded data. (See: "buf_mem_st" struct).
}

char *base64decode (const void *b64_decode_this, int decode_this_many_bytes, int dml){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    char *base64_decoded = calloc( (decode_this_many_bytes*3)/4+1, sizeof(char) ); //+1 = null.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                         //Initialize our memory source BIO.
    BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes); //Base64 data saved in source.
    BIO_push(b64_bio, mem_bio);          //Link the BIOs by creating a filter-source BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);          //Don't require trailing newlines.
    int decoded_byte_index = 0;   //Index where the next base64_decoded byte should be written.
    while ( 0 < BIO_read(b64_bio, base64_decoded+decoded_byte_index, 1) ){ //Read byte-by-byte.
        decoded_byte_index++; //Increment the index until read of BIO decoded data is complete.
        dml++;
        //printf("dml is now: %d\n",dml);
    } //Once we're done reading decoded data, BIO_read returns -1 even though there's no error.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    return base64_decoded;        //Returns base-64 decoded data with trailing null terminator.
}

void musage(){
	printf("%s\n","musage: ./qsc <1 (send) / 0 (recv)> <path to public/private key> <remote host if sending> <message if sending>\nend commands with 0 to overwrite the goAhead function and continue execution");
	exit(1);
}

void error(char *msg) {
	perror(msg);
    printf("\n%s\n","exiting in perror");
	exit(1);
}

void msgsend(unsigned char *publicKeyFile, char *rhost, unsigned char *msg){
    int sockfd;
    int n;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    int rport = 1337;
    char buf[BUFSIZE];
    int getresult;

    getresult = goAhead();
    printf("goahead in msgsend: %d\n",getresult);
    if (getresult != 49) {
        printf("%d\n",getresult);
        printf("%s\n","no go ahead in msgsend");
        musage();
    }
    printf("%s\n","goahead cleared in msgsend");
    unsigned char *message[512];
    int result;
    int msglen;
    msglen = strlen(msg);
    result = public_encrypt(msg, msglen, publicKeyFile, message);
    unsigned char propermessage[result];
    result = public_encrypt(msg, msglen, publicKeyFile, propermessage);
    printf("Encryption result: %d\n",result);
    unsigned char *encmessage = base64encode(propermessage, sizeof(propermessage));
    printf("sending: %s\n",encmessage);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
    server = gethostbyname(rhost);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", rhost);
        exit(0);
    }
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(rport);
    if (connect(sockfd, &serveraddr, sizeof(serveraddr)) < 0) {
        error("ERROR connecting");
    }
    n = write(sockfd, encmessage, strlen(encmessage));
    if (n < 0) {
        error("ERROR writing to socket");
    }
    bzero(buf, BUFSIZE);
    n = read(sockfd, buf, BUFSIZE);
    if (n < 0) 
      error("ERROR reading from socket");
    printf("Echo from server: %s", buf);
    close(sockfd);
}

// heres some copypasta C echo server code mixed in with rsa code lol
void msgrecv(unsigned char *privateKeyFile){
	int parentfd;
	int childfd;
	int lport;
	int clientlen;
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr;
	struct hostent *hostp;
	char buf[BUFSIZE];
	char *hostaddrp;
	int optval;
	int n;
    unsigned char message[1024];

    printf("file_name reference on line %d = %p\n", __LINE__, privateKeyFile);
    printf("%s\n","in msgrecv checking goAhead");
    int getresult;
    getresult = goAhead();
    printf("goahead in msgrecv: %d\n",getresult);
    if (getresult != 49) {
        printf("%d\n",getresult);
        printf("%s\n","no go ahead in recv");
    	musage();
    }
    printf("%s\n","goahead cleared in msgrecv");
	lport = 1337;
	parentfd = socket(AF_INET, SOCK_STREAM, 0);
	if (parentfd < 0) 
	error("ERROR opening socket");
	optval = 1;
	setsockopt(parentfd, SOL_SOCKET, SO_REUSEADDR, 
	     (const void *)&optval , sizeof(int));
	bzero((char *) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)lport);
	if (bind(parentfd, (struct sockaddr *) &serveraddr, 
	   sizeof(serveraddr)) < 0) 
	error("ERROR on binding");
	if (listen(parentfd, 5) < 0)
	error("ERROR on listen");
	clientlen = sizeof(clientaddr);
	while (1) {
	childfd = accept(parentfd, (struct sockaddr *) &clientaddr, &clientlen);
	if (childfd < 0) 
	  error("ERROR on accept");
	bzero(buf, BUFSIZE);
	n = read(childfd, buf, BUFSIZE);
	if (n < 0) 
	  error("ERROR reading from socket");
	printf("server received %d bytes\n", n);
    printf("received: %s\n", buf);
    int dml = 0;
    unsigned char *dc = base64decode(buf, n, dml);
    printf("created unsigned decoded buffer\n");
    int result;
    int datalen = 512;
    printf("created 512 int for datalen\n");

    // lol dumb
    //unsigned char *pointless;
    //printf("created unsigned char to hold 512 bytes\n");
    //strncpy(pointless, dc, 512);
    //printf("copied first 512 bytes of data to buffer\n");

    result = private_decrypt(dc, datalen, privateKeyFile, message);
    printf("passed decrypt: %d\n", result);
    ERR_peek_last_error();
	int i;
	for (i = 0; i < 512; i++) {
		printf("%02X",message[i]);
	}
	printf("\n");
    printf("Message decrypted: %s\n",message);
	n = write(childfd, "got it", strlen("got it"));
	if (n < 0) {
	   error("ERROR writing to socket");
    }
	close(childfd);
	exit(0);
	}
}

int main(int argc, char **argv){
	int action;
    int isok;
    char *rhost;
    unsigned char *msg;
    unsigned char *keypath;

    action = atoi(argv[1]);
    if(argc < 2){
        printf("%s\n","too few args");
    	musage();
    }

    printf("\n%d\n",action);
    
    if (action == 0){
    	action = 0;
    } else if (action == 1){
    	action = 1;
    } else {
        printf("%s","no action?");
    	musage();
    }

    printf("goahead: %d\n",goAhead());

    if (action == 1){
    	if(argc < 4){
            printf("%s","too few args for this action");
    		musage();
    	}
        isok = atoi(argv[5]);
    	if(isok < 1){
    		overwrite_goAhead();
            printf("%s\n","left overwrite_goAhead successfully");
            printf("goahead: %d\n",goAhead());
    	}
        rhost = argv[3];
        msg = argv[4];
        keypath = argv[2];
        printf("path len: %d\n",strlen(argv[2]));
        msgsend(keypath, rhost, msg);
    } else if (action == 0){
        keypath = argv[2];
        printf("file_name reference on line %d = %p\n", __LINE__, keypath);
        printf("path len: %d\n",strlen(argv[2]));
        isok = atoi(argv[3]);
    	if(isok < 1){
    		overwrite_goAhead();
            printf("%s\n","left overwrite_goAhead successfully");
            printf("goahead: %d\n",goAhead());
    	}
        printf("calling msgrecv with %s\n",keypath);
    	msgrecv(keypath);
        printf("left msgrecv\n");
    }
    printf("\n%s\n","exiting in main, end");
    exit(0);

}
