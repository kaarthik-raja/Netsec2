//SOURCES USED https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
//https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <time.h> 
#include <sys/time.h>   
#include <sys/resource.h> 
#include <openssl/err.h>
#include <openssl/conf.h>

typedef unsigned char uchr;

struct timespec start, end; 
FILE *fIN, *fOUT,*fTAG;
int EncDec=1;
int CMode=1;
int KSize=1;
int Algo=1;
const EVP_CIPHER* (*cipher_func)(void) ;

void en_de_crypt( uchr *ckey, uchr *ivec,int should_encrypt) {

    fseek(fIN, 0L, SEEK_END);
    int Intext_len = ftell(fIN);
    fseek(fIN, 0L, SEEK_SET);

    const unsigned BUFSIZE=Intext_len;
    uchr *read_buf = malloc(BUFSIZE);
    uchr *cipher_buf;
    unsigned blocksize;
    int out_len;

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new() ;

    EVP_CipherInit_ex(ctx, (*cipher_func)(),NULL ,ckey, ivec, should_encrypt);
    blocksize = EVP_CIPHER_CTX_block_size(ctx);
    cipher_buf = malloc(BUFSIZE + blocksize);
    int numRead = fread(read_buf, sizeof(uchr), BUFSIZE, fIN);
    
    clock_gettime(CLOCK_MONOTONIC, &start); 

    EVP_CipherUpdate(ctx, cipher_buf, &out_len, read_buf, numRead);
    clock_gettime(CLOCK_MONOTONIC, &end); 

    fwrite(cipher_buf, sizeof(uchr), out_len, fOUT);
    EVP_CipherFinal_ex(ctx, cipher_buf, &out_len);
    fwrite(cipher_buf, sizeof(uchr), out_len, fOUT);

    free(cipher_buf);
    free(read_buf);
}


int ccm_cipher(uchr *tag, uchr *key, uchr *iv,int should_encrypt)
{
    fseek(fIN, 0L, SEEK_END);
    int Intext_len = ftell(fIN);
    fseek(fIN, 0L, SEEK_SET);

    const unsigned BUFSIZE=Intext_len+10;
    uchr *read_buf = malloc(BUFSIZE+1);
    uchr *cipher_buf;
    unsigned blocksize;
    int out_len;

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, (*cipher_func)(), NULL, NULL, NULL,should_encrypt);

    blocksize = EVP_CIPHER_CTX_block_size(ctx);
    cipher_buf = malloc(BUFSIZE + blocksize+1);

    int ret;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL);
    if(should_encrypt)    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, NULL);
    else EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, tag);
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv,should_encrypt);
    EVP_CipherUpdate(ctx, NULL, &out_len, NULL, Intext_len);

    int numRead = fread(read_buf, sizeof(uchr), BUFSIZE, fIN);
    clock_gettime(CLOCK_MONOTONIC, &start); 

    ret =EVP_EncryptUpdate(ctx, cipher_buf, &out_len, read_buf, numRead);
    clock_gettime(CLOCK_MONOTONIC, &end); 
    fwrite(cipher_buf, sizeof(uchr), out_len, fOUT);
    
    EVP_CipherFinal_ex(ctx, cipher_buf, &out_len);
    fwrite(cipher_buf, sizeof(uchr), out_len, fOUT);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 14, tag);        
    EVP_CIPHER_CTX_free(ctx);
    return should_encrypt+ret;
}


void parser(int argc, char *argv[]);

int main(int argc, char *argv[]) {

    uchr *ckey = "CS16B108#CS6500_NetworkSecurity@OPENSSL_Analysiskey";//Note Key can be arbitarily large only the first 128,168,256 buts are used
    uchr *ivec = "CS1100-IntroToProgramming@IITM";
    uchr  tag[16];

    char *inp_file = "tiny.txt";
    char *out_file = "decrypted.txt";
    char *tag_file = "tag.txt";

    if(argc>8){
        inp_file = argv[10];
        out_file = argv[12];
    }
    parser(argc,argv);
    int i;
    long nsec;
    nsec=0;
    for(i=0;i<50;i++){
        fIN = fopen(inp_file, "rb");
        fOUT = fopen(out_file, "wb");

        if(CMode == 3){
            if(!EncDec){
                fTAG = fopen(tag_file,"rb");
                fread(tag, sizeof(uchr), 15, fTAG);
                tag[14]='\0';
                fclose(fTAG);

            }
        }

        if(CMode==3)ccm_cipher(tag,ckey,ivec,EncDec);
        else en_de_crypt(ckey, ivec,EncDec);    


        fclose(fIN);
        fclose(fOUT);
        if(CMode == 3){
            if(EncDec){
                fTAG = fopen(tag_file,"wb");
                fwrite(tag, sizeof(uchr), 15, fTAG);
                fclose(fTAG);            
            }
        }

        long seconds = end.tv_sec - start.tv_sec; 
        long ns = end.tv_nsec - start.tv_nsec; 
        if(i%5==0)        printf("%ld  %ld\n",seconds, ns );
        nsec+=1000000000*seconds+ns;
    }
    printf("Avg %ld\n",nsec/100 );
    return 0;
}

void parser(int argc, char *argv[]){
    if(!strcmp(argv[2],"Dec"))EncDec  = 0;

    if(!strcmp(argv[2],"DES"))Algo  = 2;

    if(!strcmp(argv[6],"CCM"))CMode  = 3;
    if(!strcmp(argv[6],"ECB"))CMode  = 2;
    if(!strcmp(argv[6],"CBC"))CMode  = 1;
    
    if(!strcmp(argv[8],"256"))KSize  = 2;

    if(Algo ==1){//AES ENCRYPTION
        if(CMode == 3){ //CCM
            if(KSize==2){ 
                cipher_func =  &EVP_aes_256_ccm;
                printf("cipher_func is %s\n", "EVP_aes_256_ccm");
            }
            else{ 
                cipher_func = &EVP_aes_128_ccm;
                printf("cipher_func is %s\n", "EVP_aes_128_ccm");
            }
        }
        else{//ECB
            if(KSize == 2){
                cipher_func = &EVP_aes_256_ecb;
                printf("cipher_func is %s\n", "EVP_aes_256_ecb");
            }
            else{
                cipher_func = &EVP_aes_128_ecb; 
                printf("cipher_func is %s\n", "EVP_aes_128_ecb");
            }
        }
    }
    else{
        cipher_func = &EVP_des_ede3_cbc;
        printf("cipher_func is %s\n", "EVP_des_ede3_cbc");
    }
    printf("Enc Dec%d\n", EncDec);
    // cipher_func = &EVP_aes_256_ccm;

}