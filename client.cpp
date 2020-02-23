//Code
#include <bits/stdc++.h>

#include <sys/types.h> 
#include <sys/socket.h> 
#include <sys/time.h>

#include <netdb.h>
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <unistd.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

using namespace std;

#define MAX 1000
#define G_MY_IP "127.0.0.1"
#define ff first
#define ss second
#define pb push_back

#define TRACE
#ifdef TRACE
    #define trace(...) __f(#__VA_ARGS__, __VA_ARGS__)
        
    template <typename Arg1>
    void __f(const char* name, Arg1&& arg1){
        cerr << name << ": " << arg1 << std::endl;
    }
 
    template <typename Arg1, typename... Args>
    void __f(const char* names, Arg1&& arg1, Args&&... args){
        const char* comma = strchr(names + 1, ',');
        cerr.write(names, comma - names) << ": " << arg1<<" |";
        __f(comma+1, args...);
    }
#else
    #define trace(...) ;
#endif

unordered_map<string,int> mpi;

typedef unsigned char uchar;


typedef struct cargs
{
    int SR;
    short kdc_port, my_port ;
    char my_name[20],you_name[20];
    char kdc_ip[21];
    char *inpf , *outf;
    char my_key[17];
    int Nonce;
    char my_IP[21];


}cargs;


typedef struct node
{
    int sig_num;
    char cipher[500],dec_cipher[500];
    char ocipher[500],dec_message[500];
    char my_ID[21],you_ID[21],Ks[10];
    char my_IP[21],you_IP[21];
    int my_port,you_port;
    char extra[30];
    // uchar 
}node;

//Global Variables
int t_size;
node info;
cargs argvs;
struct sockaddr_in my_addr, you_addr, kdc_addr; 
int addr_len; 

char choice[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
char *message;
int message_len;
int kdc_sock , you_sock , my_sock ,sock;
int opt = 1; 

void handleErrors(void);
uchar *base64(uchar *input, int length);
int encrypt(uchar *, int , uchar *key, uchar *iv, uchar *, int alg = 1, uchar* tag = NULL);
int decrypt(uchar *, int , uchar *key, uchar *iv, uchar *, int alg = 1, uchar* tag = NULL);
int encr_base(char* inp,char* out, char* key,int len);
int unbase_decr(char* inp,char* out, char* key,int len);
int parser(int argc, char *argv[]);
int sig_parser(char *sig);
void cpy_str(char *& sig,char* &ptr);
void generate_key();
int register_key(void);
void create_client(int &sock,struct sockaddr_in &addr);
void create_server();
void accept_conn();

void Nonce_func(void);

int main(int argc, char *argv[]) {
    srand(time(0));
    char buff[MAX],buff2[MAX];
    
    char buff3[MAX] ;   //For Dummy Checks
    
    addr_len = sizeof(my_addr); 
    memset(&my_addr, 0,addr_len); 
    memset(&kdc_addr, 0, addr_len); 
    memset(&you_addr, 0, addr_len); 
      
    char continue_ops;

	//Process input
    int p_err = parser(argc,argv);

	if(p_err){
		printf("%s\n", "We have a error in input cmd line argument");
		printf("Check argv[%d] = \"%s\"\n", p_err,argv[p_err] );
	}

    generate_key();

    if(register_key()){
        printf("%s\n","Error in registration" );
        return 0;
    }

    // printf("\nContinue with sending message(y/n): ");
    // scanf("%c",&continue_ops);
    // 
    // if(continue_ops == 'n'){
    if(0){
        return 0;
    }

    if(argvs.SR){
        //STEP 1
        create_client(kdc_sock,kdc_addr);
        strcpy(buff,argvs.my_name );
        strcat(buff,"#" );
        strcat(buff,argvs.you_name );
        strcat(buff,"#" );

        argvs.Nonce = rand()%1000000;
        string s = to_string(argvs.Nonce);
        strcat(buff,s.c_str());//Nonce
        // strcat(buff,"#" );
        printf("E_ka %s\n",buff );
        encr_base(buff,buff2,argvs.my_key ,strlen(buff) );
        printf("encrpyt %s -> %s -- \n",buff,buff2 );
        strcpy(buff,"305#" );
        strcat(buff, buff2 );
        strcat(buff,"#" );
        strcat(buff,argvs.my_name );
        // strcat(buff,"#" );

        printf("Sending to KDC %s\n", buff);
        send(kdc_sock , buff, strlen(buff ),0 );
        memset(buff,0,MAX);
        printf("reading from kdc\n");
        read( kdc_sock , buff, 1024); 
        printf("Received for 305 %s\n", buff);
        close(kdc_sock);


        sig_parser(buff);

        //STEP 2:
        // system("PAUSE");

        strcpy(buff,"309#" );
        strcat(buff, info.ocipher );
        strcat(buff,"#" );
        strcat(buff,argvs.my_name);        
        strcat(buff,"#" );

        //you_addr send
        printf("Creating client socket %s\n",buff );
        create_client(you_sock,you_addr);

        // return 0;
        send(you_sock , buff, strlen(buff ) ,0);
        memset(buff,0,MAX);
        read(you_sock , buff, 1024); 

        printf("Received for 309 - 310 %s\n", buff);

        //Step 3:
        sig_parser(buff);


        strcpy(buff,message);
        strcat(buff,"#");
        strcat(buff, to_string(argvs.Nonce+1).c_str()  );
        strcat(buff,"#");
        encr_base( buff, buff2, info.Ks ,strlen(buff) );


        strcpy(buff, "311#");
        strcat(buff, buff2 );
        strcat(buff,"#" );
        strcat(buff, argvs.my_name );
        strcat(buff,"#" );

        // close(you_sock );
        // create_client(you_sock,you_addr);
        printf("Sent to B message %s\n", buff );
        send(you_sock , buff, strlen(buff ) ,0);
        memset(buff,0,MAX);

        read(you_sock , buff, 1024); 
        printf("Got from B message %s\n", buff );
        
        close(you_sock);
    }

    else{
        create_server();
        printf("R created server and listening %s\n",  "...");
        memset(buff,0,MAX);

        read(you_sock, buff,1024);
        printf("Received 309 - %s\n", buff);
        sig_parser(buff);

        strcpy(buff,info.you_ID );
        strcat(buff,"#");
        strcat(buff,info.my_ID );
        strcat(buff,"#");
        strcat(buff,to_string(argvs.Nonce).c_str());//Nonce
        strcat(buff,"#" );
        Nonce_func();
        strcat(buff,to_string(argvs.Nonce).c_str());//Nonce
        strcat(buff,"#" );
        encr_base(buff,buff2, info.Ks ,strlen(buff) );
        
        strcpy(buff, "310#");
        strcat(buff, buff2 );
        strcat(buff,"#" );
        strcat(buff, argvs.my_name );
        strcat(buff,"#" );

        printf("Sending for 310 %s\n",buff );
        send(you_sock , buff, strlen(buff ),0 );

        // close(you_sock );
        // accept_conn();

        memset(buff,0,MAX);
        read(you_sock, buff,1024);
        printf("Got 311 end  %s\n", buff);
        sig_parser(buff);
        printf("Secret Message is: %s\n",info.dec_message );
        strcpy(buff,"312#Successfull#");
        send(you_sock , buff, strlen(buff ),0 );
        printf("sent back 312 %s\n",buff );
        close(you_sock);

    }


    close(sock);
    return 0;
}



int parser(int argc, char *argv[]){
    if(argc > 13) return 13;
    if(strcmp(argv[1],"-n"))return 1;
    if(strcmp(argv[3],"-m"))return 3;
    
    strcpy(argvs.my_name ,argv[2]);

    strcpy(argvs.my_IP, G_MY_IP );

    if(!strcmp(argv[4],"S")){
        argvs.SR  = 1 ;    
        argvs.my_port = 8010;
        if(strcmp(argv[5],"-o"))return 5;
    	if(strcmp(argv[7],"-i"))return 7;

        strcat(argvs.you_name , argv[6]);
        argvs.inpf = argv[8];

        FILE *fIN;
        fIN = fopen(argv[8], "r");
        fseek(fIN, 0L, SEEK_END);
        message_len = ftell(fIN);
        fseek(fIN, 0L, SEEK_SET);
        message = (char *)malloc(message_len+5);
        int len2  = fread(message, sizeof(char), message_len, fIN);
        if(message_len!= len2){printf("%s\n","in parser length mismatch" );}
        fclose(fIN);


    }
    else if(!strcmp(argv[4],"R")){
        argvs.SR  = 0;
        argvs.my_port = 8012;

    	if(strcmp(argv[5],"-s"))return 5;
    	if(strcmp(argv[7],"-o"))return 7;

        argvs.inpf = argv[6];
        argvs.outf = argv[8];
    }
    else return 4;

    if(strcmp(argv[9],"-a"))return 9;
    if(strcmp(argv[11],"-p"))return 11;

    strcpy(argvs.kdc_ip,argv[10]);
    argvs.kdc_port =  atoi(argv[12]);



    kdc_addr.sin_family = AF_INET; 
    // kdc_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
    kdc_addr.sin_addr.s_addr = inet_addr(argv[10]);
    kdc_addr.sin_port = htons(argvs.kdc_port); 


    my_addr.sin_family = AF_INET; 
    // my_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
    my_addr.sin_addr.s_addr = inet_addr(argvs.my_IP);
    my_addr.sin_port = htons(argvs.my_port); 



    return 0;
}
void cpy_str(char *& sig,char* ptr){
    int i=0;
    for(i=0;sig[i]!='#' && sig[i]!='\0';i++ );
    sig[i]='\0'; i++;
    for(int j=0;j<i;j++)ptr[j] = sig[j];
    // ptr = sig;
    sig =sig + i;
    while (*sig == '#')sig++;       
}

int sig_parser(char *sig){
    // char *sig;//signal is a const buff array
    // sig = signal;

    if(sig[3]=='#'){
        sig[3]='\0';
        info.sig_num = atoi(sig);
        sig = sig+4;
    }else return 1;

    if(info.sig_num == 302){
        int i;
        for(i=0;sig[i]!='#';i++ );
        sig[i]='\0';
        printf("Signal compared %s\n",sig );
        return strcmp(sig ,argvs.my_name);
    }
    else{
        cpy_str(sig, info.cipher);
        // printf("Cipher received is %s\n", info.cipher );

    } 
    


    if(info.sig_num == 306 || info.sig_num == 309){
        unbase_decr(info.cipher ,info.dec_cipher, argvs.my_key,strlen (  info.cipher) );
        printf("%s decipher with %s is %s -fin>\n", info.cipher , argvs.my_key, info.dec_cipher );
        char *decipher = info.dec_cipher;
        cpy_str(decipher, info.Ks);
        cpy_str(decipher, info.you_ID);
        cpy_str(decipher, info.my_ID);
        cpy_str(decipher, info.extra);
        argvs.Nonce = atoi(info.extra);
        cpy_str(decipher, info.you_IP);
        cpy_str(decipher, info.extra);
        info.you_port=atoi(info.extra);
        if(info.sig_num == 306){
            cpy_str(decipher, info.ocipher);
            printf("decrypted signal %s\n", info.ocipher);

        you_addr.sin_family = AF_INET; 
    // you_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
        you_addr.sin_addr.s_addr = inet_addr(info.you_IP);
        you_addr.sin_port = htons(info.you_port); 
            
        }
        if(info.sig_num == 309){
            cpy_str(sig, info.you_ID);
        }


    }  

    else if(info.sig_num == 310){
        cpy_str(sig, info.my_ID); 
        unbase_decr(info.cipher ,info.dec_cipher, info.Ks,strlen (info.cipher) );
        printf("%s decipher with %s is %s -fin>\n", info.cipher , info.Ks , info.dec_cipher );
        char *decipher = info.dec_cipher;
        cpy_str(decipher, info.my_ID);
        cpy_str(decipher, info.you_ID);
        cpy_str(decipher, info.extra);
        if (atoi(info.extra) != argvs.Nonce ){
            printf("Nonce Mismatch in 310 %d %s\n" , argvs.Nonce, info.extra);
            exit(0);
        }
        cpy_str(decipher,info.extra);
        argvs.Nonce = atoi(info.extra );
    }
    else if(info.sig_num == 311 ){
        cpy_str(sig, info.my_ID); 
        printf("%s decipher with %s is %s -fin>\n", info.cipher , info.Ks , info.dec_cipher );
        unbase_decr(info.cipher ,info.dec_cipher, info.Ks,strlen (info.cipher) );
        char *decipher = info.dec_cipher;
        cpy_str(decipher, info.dec_message );
        cpy_str(decipher, info.extra);
        if (atoi(info.extra) != argvs.Nonce+1 ){
            printf("Nonce Mismatch in 311\n");
            exit(0);
        }

    }
    return  0;
}

void generate_key(void){
    if(argvs.SR ){
        for (int i = 0; i < 12; ++i)
        {
            argvs.my_key[i] = 'A'+i;
        }
    }
    else{
        for (int i = 0; i < 12; ++i){
            argvs.my_key[i] = 'Z'-i;
        }   
    }
    // for (int i = 0; i < 12; ++i)
    // {
    //     argvs.my_key[i] = choice[rand()%62];
    // }
    for (int i = 12; i < 16; ++i)
    {
        argvs.my_key[i] = '#';
    }
    argvs.my_key[16] = '\0';
    printf("%s\n",argvs.my_key);

}

int register_key(void){

    create_client(kdc_sock,kdc_addr);
    
    char buff[2000];
    strcpy(buff,"301#");
    strcat(buff,argvs.my_IP);
    strcat(buff,"#");
    strcat(buff,to_string(argvs.my_port).c_str());
    strcat(buff,"#");
    strcat(buff,argvs.my_key);
    strcat(buff,"#");
    strcat(buff,argvs.my_name);
    strcat(buff,"#");

    printf("Sending to KDC %s\n",buff );

    send(kdc_sock, buff, strlen(buff),0);
    printf("Sent\n");
    read(kdc_sock,buff ,1024);
    printf("Received %s\n",buff);

    close(kdc_sock);
    return sig_parser(buff);

}

void  create_client(int &sock,struct sockaddr_in &addr){
    if ( (sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        trace("socket creation failed");
        exit(EXIT_FAILURE); 
    } 
    // if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
    //                                               &opt, sizeof(opt))) 
    // { 
    //     perror("setsockopt"); 
    //     exit(EXIT_FAILURE); 
    // } 
    // if ( bind(sock, (const struct sockaddr *)&my_addr,addr_len) < 0 ) 
    // { 
    //     perror("bind failed");
    //     exit(EXIT_FAILURE); 
    // }

    if (connect(sock, (struct sockaddr *)&addr, addr_len) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return ; 
    } 
}

void  create_server(){
    if ( (my_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        trace("socket creation failed");
        exit(EXIT_FAILURE); 
    } 

    if ( bind(my_sock, (const struct sockaddr *)&my_addr,addr_len) < 0 ){ 
        perror("bind failed");
        exit(EXIT_FAILURE); 
    }

    if (listen(my_sock, 5) != 0){ 
        printf("Listen failed...\n"); 
        trace("Listen failed...\n");
        exit(0); 
    } 
    else{
        printf("Server listening..\n"); 
        trace("Server listening..\n");
    }
    you_sock = accept(my_sock,(sockaddr*)&you_addr,(socklen_t*)&addr_len);
    if(you_sock < 0){
        cout<<"Connect failed"<<"\n";
        trace("Connect failed");
    }
    else{
        cout<<"Server connected to new client"<<"\n";
        trace("Server connected to new client");
    }
}
void accept_conn(){
    you_sock = accept(sock,(sockaddr*)&you_addr,(socklen_t*)&addr_len);
    if(you_sock < 0){
        cout<<"Connect failed"<<"\n";
        trace("Connect failed");
    }
    else{
        cout<<"Server connected to new client"<<"\n";
        trace("Server connected to new client");
    }
}

void Nonce_func(void){
    argvs.Nonce +=1;
}


void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

uchar *base64(uchar *input, int length){
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    
    uchar *buff = (uchar *)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;
    
    BIO_free_all(b64);
    
    return buff;
}

uchar *unbase64(uchar *input, int length,int rl){
    BIO *b64, *bmem;
    
    uchar *buffer = (uchar *)malloc(length);
    memset(buffer, 0, length);
    int pad = 0;
    if(input[length-2] == '=' && input[length-3] == '=')
    {
        pad = 2;
    }
    else if(input[length-2] == '=')
    {
        pad=1;
    }

    //cout<<length<<" "<<"len"<<"\n";
    float temp = rl-1;

    t_size = ceil(temp/4.0);
    t_size *= 3;
    t_size -= pad;
    t_size--;
    
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    
    BIO_read(bmem, buffer, length);
    
    BIO_free_all(bmem);
    
    return buffer;
}

int encrypt(uchar *plaintext, int plaintext_len, uchar *key, uchar *iv, uchar *ciphertext, int alg, uchar* tag){
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(alg == 1)
    {
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
        handleErrors();
    }
    else if(alg == 2)
    {
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))
        handleErrors();
    }
    else if(alg == 4)
    {
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
        handleErrors();

        /*
        * Setting IV len to 7. Not strictly necessary as this is the default
        * but shown here for the purposes of this example.
        */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
            handleErrors();

        /* Set tag length */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, NULL);

        /* Initialise key and IV */
        if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
            handleErrors();
    }
    else if(alg == 5)
    {
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL))
        handleErrors();

        /*
        * Setting IV len to 7. Not strictly necessary as this is the default
        * but shown here for the purposes of this example.
        */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
            handleErrors();

        /* Set tag length */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, NULL);

        /* Initialise key and IV */
        if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
            handleErrors();
    }
    else
    {
        if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv))
        handleErrors();
    }
    

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();

    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    if(alg == 4 || alg == 5)
    {
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 14, tag))
        handleErrors();
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    //cout<<ciphertext_len<<"::";
    //cout<<endl;

    return ciphertext_len;
}

int decrypt(uchar *ciphertext, int ciphertext_len, uchar *key, uchar *iv, uchar *plaintext, int alg, uchar* tag){
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */

    if(alg == 1)
    {
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
        handleErrors();
    }
    else if(alg == 2)
    {
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))
        handleErrors();
    }
    else if(alg == 4)
    {
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
        handleErrors();

        /* Setting IV len to 7. Not strictly necessary as this is the default
        * but shown here for the purposes of this example */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
            handleErrors();

        /* Set expected tag value. */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, tag))
            handleErrors();

        /* Initialise key and IV */
        if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
            handleErrors();
    }
    else if(alg == 5)
    {
        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL))
        handleErrors();

        /* Setting IV len to 7. Not strictly necessary as this is the default
        * but shown here for the purposes of this example */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
            handleErrors();

        /* Set expected tag value. */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, tag))
            handleErrors();

        /* Initialise key and IV */
        if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
            handleErrors();
    }
    else
    {
        if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv))
        handleErrors();
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(alg != 4 && alg != 5)
    {
        if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
            handleErrors();
        plaintext_len += len;
    }

    //cout<<plaintext_len<<"--";
    //cout<<endl;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


int encr_base(char* inp1,char* out1, char* key1,int len){
    uchar* inp = (uchar*)inp1;
    uchar* out = (uchar*)out1; 
    uchar* key = (uchar*)key1;
    unsigned char *iv_128 = (unsigned char *)"0123456789012345";
    int text_len;
    unsigned char temp[MAX];unsigned char* o1;
    text_len = encrypt (inp, len, key, iv_128,
                              temp,1,NULL);
    temp[text_len]='\0';
    o1 = base64(temp,text_len+1);

    int c=0;
    while(o1[c] != '\0')
    {
        out[c]=o1[c];c++;
    }
    out[c]='\0';
    return c;
}

int unbase_decr(char* inp1,char* out1, char* key1,int len){
    uchar* inp = (uchar*)inp1;
    uchar* out = (uchar*)out1; 
    uchar* key = (uchar*)key1;
    unsigned char *iv_128 = (unsigned char *)"0123456789012345";
    inp[len]='\n';
    inp[len+1]='\0';
    int rl=0;
    for(int i=0;i<len;i++)
    {
        if(inp[i] != '\n') rl++;
    }
    unsigned char * plaintext=unbase64(inp,len+1,rl);
    int filesize = t_size;int text_len;

    //decrypt
    trace("Starting Dec",len+1);
    text_len = decrypt(plaintext, filesize, key, iv_128,
                                out,1,NULL);
    // free(plaintext);                                

    out[text_len]='\0';
    return text_len;
}
