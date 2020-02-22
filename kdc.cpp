#include <bits/stdc++.h>
#include <stdio.h> 
#include <sys/time.h>
#include <netdb.h>
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <pthread.h> 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <bits/stdc++.h>
#include<sys/time.h>
using namespace std;
#define MAX 1000
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
typedef struct node
{
    string ip,port,pass;
}node;
vector<node> info;
int t_size;
timeval tim;
long long start_t,end_t;float tot;

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

unsigned char *base64(unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    
    unsigned char *buff = (unsigned char *)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;
    
    BIO_free_all(b64);
    
    return buff;
}

unsigned char *unbase64(unsigned char *input, int length,int rl)
{
    BIO *b64, *bmem;
    
    unsigned char *buffer = (unsigned char *)malloc(length);
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

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext, int alg, unsigned char* tag)
{
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
    gettimeofday(&tim,NULL);
	start_t=tim.tv_sec*1000000 + tim.tv_usec;

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    gettimeofday(&tim,NULL);
	end_t=tim.tv_sec*1000000 + tim.tv_usec;
    tot+= end_t-start_t;

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

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, int alg, unsigned char* tag)
{
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
    gettimeofday(&tim,NULL);
	start_t=tim.tv_sec*1000000 + tim.tv_usec;
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    gettimeofday(&tim,NULL);
	end_t=tim.tv_sec*1000000 + tim.tv_usec;
    tot+= end_t-start_t;
    
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

void build_ds(char* pwdfile)
{
    mpi.clear();
    info.clear();

    trace("In build ds");
    FILE* optr = fopen(pwdfile,"r");
    char ch=fgetc(optr);string te="";
    int in=0;
    while(ch != EOF)
    {
        te="";
        ch=fgetc(optr);
        while(ch != ':')
        {
            te+=ch;
            ch=fgetc(optr);
        }
        trace(te);
        mpi[te]=in;in++;
        node temp;
        temp.ip="";
        ch=fgetc(optr);
        while(ch != ':')
        {
            temp.ip+=ch;
            ch=fgetc(optr);
        }
        temp.port="";
        trace(temp.ip);
        ch=fgetc(optr);
        while(ch != ':')
        {
            temp.port+=ch;
            ch=fgetc(optr);
        }
        trace(temp.port);
        temp.pass="";
        ch=fgetc(optr);
        while(ch != '\n' && ch != EOF)
        {
            temp.pass+=ch;
            ch=fgetc(optr);
        }
        ch=fgetc(optr);
        trace(temp.pass);
        info.pb(temp);
    }
    fclose(optr);
}

void write_ds(char* pwdfile)
{
    FILE* optr = fopen(pwdfile,"w");
    unordered_map<string,int> ::iterator it;
    int l=0;
    for(it=mpi.begin();it != mpi.end();it++)
    {
        trace("Wrting ds: ",it->ff);
        fputc(':',optr);
        l=it->ff.length();
        for(int i=0;i<l;i++)
        {
            fputc(it->ff[i],optr);
        }
        fputc(':',optr);
        l=info[it->ss].ip.length();
        for(int i=0;i<l;i++)
        {
            fputc(info[it->ss].ip[i],optr);
        }
        fputc(':',optr);
        l=info[it->ss].port.length();
        for(int i=0;i<l;i++)
        {
            fputc(info[it->ss].port[i],optr);
        }
        fputc(':',optr);
        l=info[it->ss].pass.length();
        for(int i=0;i<l;i++)
        {
            fputc(info[it->ss].pass[i],optr);
        }
        fputc('\n',optr);
    }
    fclose(optr);
}

void reg_cli(char* buff)
{
    node temp;string name="";
    temp.ip=temp.port=temp.pass="";
    int in=4;
    while(buff[in] != '#')
    {
        temp.ip+=buff[in];in++;
    }
    while(buff[in] == '#')
    {
        in++;
    }
    while(buff[in] != '#')
    {
        temp.port+=buff[in];in++;
    }
    while(buff[in] == '#')
    {
        in++;
    }
    int pass_size=0;
    while(buff[in] != '#')
    {
        temp.pass+=buff[in];in++;
        pass_size++;
    }
    while(pass_size < 16)
    {
        temp.pass+='#';
        pass_size++;
    }
    while(buff[in] == '#')
    {
        in++;
    }
    while(buff[in] != '#' && buff[in] != '\0')
    {
        name+=buff[in];in++;
    }
    //encrypt and encode pass here
    unsigned char *output,plaintext[MAX],text[MAX];
    int text_len=0;
    trace(temp.pass);
    unsigned char *key_128 = (unsigned char *)"0123456789012345";
    unsigned char *iv_128 = (unsigned char *)"0123456789012345";
    for(int i=0;i<temp.pass.length();i++)
    {
        plaintext[i]=temp.pass[i];
    }
    plaintext[16]='\0';

    text_len = encrypt (plaintext, pass_size, key_128, iv_128,
                              text,1,NULL);
    text[text_len]='\0';
    output = base64(text,text_len+1);

    in=0;temp.pass="";
    while(output[in] != '\0')
    {
        temp.pass+=output[in];in++;
    }
    free(output);

    if(mpi.find(name) != mpi.end())
    {
        trace("Found ",name);
        info[mpi[name]]=temp;
        trace(info[mpi[name]].ip,info[mpi[name]].pass);
    }
    else
    {
        trace("New Entry ",name);
        mpi[name]=info.size();
        info.pb(temp);
    }

    buff[0]='3';buff[1]='0';buff[2]='2';buff[3]='#';
    for(int i=0;i<name.length();i++)
    {
        buff[i+4]=name[i];
    }
    buff[4+name.length()]='\0';
}

int encr_base(unsigned char* inp,unsigned char* out,
    unsigned char* key,int len)
{
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

int unbase_decr(unsigned char* inp,unsigned char* out,
    unsigned char* key,int len)
{
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
    free(plaintext);                                

    out[text_len]='\0';
    return text_len;
}

void gen_key(char* buff)
{
    string name;
    unsigned char encr[MAX],text[MAX],kb[MAX],ka[MAX],key_a[MAX],key_b[MAX];
    int in=0,len;int rl=0,rl1=0;int len1;
    int text_len;
    unsigned char *key_128 = (unsigned char *)"0123456789012345";
    unsigned char *iv_128 = (unsigned char *)"0123456789012345";
    while(buff[in+4] != '#')
    {
        encr[in]=buff[in+4];
        if(buff[in+4] != '\n') rl++;
        in++;
    }
    encr[in]='\0';
    len=in;
    while(buff[in+4] == '#')
    {
        in++;
    }
    while(buff[in+4] != '#' && buff[in+4] != '\0')
    {
        name+=buff[in+4];in++;
    }
    trace(name,info[mpi[name]].pass);
    //unbase
    for(int i=0;i<info[mpi[name]].pass.length();i++)
    {
        ka[i]=info[mpi[name]].pass[i];
    }
    len1=info[mpi[name]].pass.length();
    int key_len_a,key_len_b;
    unsigned char temp[MAX];
    int temp_len;
    
    key_len_a = unbase_decr(ka,key_a,key_128,len1);
    trace(key_a);
    
    //decrypt A
    /*
    text_len = encr_base(key_a,text,key_128,key_len_a);
    trace(text,text_len);
    */
    //remove
    trace(encr,len);
    text_len = encr_base(encr,text,key_a,len);
    trace(text,text_len);
    

    temp_len = unbase_decr(text,temp,key_a,text_len);
    trace(temp,temp_len);
    //remove
    for(int i=0;i<temp_len;i++)
    {
        if(temp[i] == '$') temp[i]='#';
    }
    trace(temp);

    string ida="",idb="",nonce1="";
    in=0;
    while(temp[in] != '#') 
    {
        ida+=temp[in];in++;
    }
    while(temp[in] == '#') 
    {
        in++;
    }
    while(temp[in] != '#') 
    {
        idb+=temp[in];in++;
    }
    while(temp[in] == '#') 
    {
        in++;
    }
    while(temp[in] != '#' && in < temp_len) 
    {
        nonce1+=temp[in];in++;
    }
    trace(ida,idb,nonce1);

    unsigned char e_ka[MAX],e_kb[MAX];
    int e_ka_len,e_kb_len;string ks="";
    //ge ks
    int rnum;
    for(int i=0;i<8;i++)
    {
        rnum=rand()%62;
        if(rnum < 26)
        {
            ks+=(char)('a'+rnum);
        }
        else if(rnum > 51)
        {
            ks+=(char)('0'+rnum-52);
        }
        else
        {
            ks+=(char)('A'+rnum-26);
        }
    }
    trace(ks);
    //encrypt B
    for(int i=0;i<info[mpi[idb]].pass.length();i++)
    {
        kb[i]=info[mpi[idb]].pass[i];
    }
    len1=info[mpi[idb]].pass.length();
    kb[len1]='\0';
    trace(kb,len);
    
    key_len_b = unbase_decr(kb,key_b,key_128,len1);
    trace(key_b,key_len_b);

    in=0;
    for(int i=0;i<ks.length();i++)
    {
        temp[in]=ks[i];in++;
    }
    temp[in]='#';in++;
    for(int i=0;i<ida.length();i++)
    {
        temp[in]=ida[i];in++;
    }
    temp[in]='#';in++;
    for(int i=0;i<idb.length();i++)
    {
        temp[in]=idb[i];in++;
    }
    temp[in]='#';in++;
    for(int i=0;i<nonce1.length();i++)
    {
        temp[in]=nonce1[i];in++;
    }
    temp[in]='#';in++;
    for(int i=0;i<info[mpi[ida]].ip.length();i++)
    {
        temp[in]=info[mpi[ida]].ip[i];in++;
    }
    temp[in]='#';in++;
    for(int i=0;i<info[mpi[ida]].port.length();i++)
    {
        temp[in]=info[mpi[ida]].port[i];in++;
    }

    temp[in]='\0';temp_len=in;
    trace(temp,temp_len);
    e_kb_len = encr_base(temp,e_kb,key_b,temp_len);
    trace(e_kb,e_kb_len);

    //remove
    text_len = unbase_decr(e_kb,text,key_b,e_kb_len);
    trace(text,text_len);

    //encrypt A
    in=0;
    for(int i=0;i<ks.length();i++)
    {
        temp[in]=ks[i];in++;
    }
    temp[in]='#';in++;
    for(int i=0;i<ida.length();i++)
    {
        temp[in]=ida[i];in++;
    }
    temp[in]='#';in++;
    for(int i=0;i<idb.length();i++)
    {
        temp[in]=idb[i];in++;
    }
    temp[in]='#';in++;
    for(int i=0;i<nonce1.length();i++)
    {
        temp[in]=nonce1[i];in++;
    }
    temp[in]='#';in++;
    for(int i=0;i<info[mpi[idb]].ip.length();i++)
    {
        temp[in]=info[mpi[idb]].ip[i];in++;
    }
    temp[in]='#';in++;
    for(int i=0;i<info[mpi[idb]].port.length();i++)
    {
        temp[in]=info[mpi[idb]].port[i];in++;
    }
    temp[in]='#';in++;
    for(int i=0;i<e_kb_len;i++)
    {
        temp[in]=e_kb[i];
        in++;
    }

    temp[in]='\0';temp_len=in;
    trace(temp,temp_len);
    e_ka_len = encr_base(temp,e_ka,key_a,temp_len);
    trace(e_ka,e_ka_len);

    //remove
    text_len = unbase_decr(e_ka,text,key_a,e_ka_len);
    trace(text,text_len);

    buff[0]='3';buff[1]='0';buff[2]='6';buff[3]='#';
    in=0;
    while(in < e_ka_len)
    {
        buff[in+4]=e_ka[in];
        in++;
    }
    buff[in+4]='\0';
}

int main(int argc,char* argv[])
{
    srand(time(0));
    char* outfile,*pwdfile;
    int port_num;
    for(int i=1;i<6;i+=2)
    {
        //trace(argv[i][1]);
        if(argv[i][1] == 'p')
        {
            port_num=atoi(argv[i+1]);
        }
        else if(argv[i][1] == 'o')
        {
            outfile=argv[i+1];
        }
        else
        {
            pwdfile=argv[i+1];
        }
    }

    int sockfd;
    bool buffer[MAX];
    freopen(outfile, "a", stderr);
    trace("Starting new Log: \n\n\n\n");
    struct sockaddr_in servaddr, cliaddr; 
    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        trace("socket creation failed");
        exit(EXIT_FAILURE); 
    } 
      
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
      
    // Filling server information 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(port_num); 
    //trace(port_num);
      
    // Bind the socket with the server address 
    if ( bind(sockfd, (const struct sockaddr *)&servaddr,sizeof(servaddr)) < 0 ) 
    { 
        perror("bind failed");
        exit(EXIT_FAILURE); 
    }

    if (listen(sockfd, 5) != 0) 
    { 
        printf("Listen failed...\n"); 
        trace("Listen failed...\n");
        exit(0); 
    } 
    else
    {
        printf("Server listening..\n"); 
        trace("Server listening..\n");
    }
    
    unsigned int len = sizeof(cliaddr);
    char buff[MAX];

    while(1)
    {
        int connfd = accept(sockfd,(sockaddr*)&cliaddr,&len);
        if(connfd < 0)
        {
            cout<<"Connect failed"<<"\n";
            trace("Connect failed");
        }
        else
        {
            cout<<"Server connected to new client"<<"\n";
            trace("Server connected to new client");
        }
        build_ds(pwdfile);
        trace("Build ds");

        read(connfd, buff, sizeof(buff));
        trace("Read data");
        if(buff[2] == '1')
        {
            trace("Entering reg_cli");
            reg_cli(buff);
            write(connfd,buff,sizeof(buff));
            trace("Sent packet as: ");
        }
        else
        {
            trace("Entering gen_key");
            gen_key(buff);
            write(connfd,buff,sizeof(buff));
            trace("Sent packet as: ");
            trace(buff);
        }

        write_ds(pwdfile);
        trace("Wrote ds");
    }

    close(sockfd);
    return 0;
}