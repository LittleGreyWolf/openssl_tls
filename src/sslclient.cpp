#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string>
#ifdef _WIN32
#include<WinSock2.h>
#else
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <openssl/rsa.h>     
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#ifdef _WIN32
#pragma comment(lib,"ws2_32.lib")
#endif

//是否加载客户端证书(双向认证时开启)
//#define LOAD_CLIENT_CERT

int main () {
    SSL_CTX *clientCTX = NULL;
    SSL* clientSSL = NULL;

    // openssl 初始化
    SSL_load_error_strings(); 
    SSL_library_init();/*初始化*/
    
    /*申请SSL会话环境*/
    clientCTX = SSL_CTX_new(TLSv1_2_client_method());
    if(clientCTX == NULL){
        ERR_print_errors_fp(stderr);
        printf("SSL_CTX_new failed!\n");
        return -1;
    }       

    // /*申请一个SSL套接字*/
    clientSSL = SSL_new(clientCTX);
    if(clientSSL == NULL){
        ERR_print_errors_fp(stderr);
        printf("SSL_new failed.\n");
        return -1;
    }

    printf("SSL_new success\n");

    // 获取可执行程序路径
#ifdef _WIN32
	char cExeName[256] = {0};
	GetModuleFileName(NULL, cExeName, sizeof(cExeName) - 1);
	std::string strExeName(cExeName); 
	std::string strExeNamePath;
	strExeNamePath = strExeName.substr(0, strExeName.rfind("\\"));
#endif

    // 检验服务端证书
    SSL_CTX_set_verify(clientCTX,SSL_VERIFY_PEER,NULL);
#ifdef _WIN32
    std::string caCertName = strExeNamePath + "\\ca.crt";
    SSL_CTX_load_verify_locations(clientCTX,caCertName.c_str(),NULL); 
#else
    SSL_CTX_load_verify_locations(clientCTX,"./ca.crt",NULL); 
#endif


    // 双向认证时开启
    /*加载客户端证书*/
#if defined(_WIN32) && defined(LOAD_CLIENT_CERT)
    std::string clientCertName = strExeNamePath + "\\client.crt";
    if (SSL_CTX_use_certificate_file(clientCTX, clientCertName.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
#elif defined(LOAD_CLIENT_CERT)
    if (SSL_CTX_use_certificate_file(clientCTX, "./client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
#endif

    /*加载自己的私钥,以用于签名*/
#if defined(_WIN32) && defined(LOAD_CLIENT_CERT)
    std::string clientKeyName = strExeNamePath + "\\client.key";
    if (SSL_CTX_use_PrivateKey_file(clientCTX, clientKeyName.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
#elif defined(LOAD_CLIENT_CERT)
    if (SSL_CTX_use_PrivateKey_file(clientCTX, "./client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
#endif

#if defined(LOAD_CLIENT_CERT)
    /*调用了以上两个函数后,检验一下自己的证书与私钥是否配对*/
    if (!SSL_CTX_check_private_key(clientCTX)) {
        printf("Private key does not match the certificate public key\n");
        return -1;
    }  
#endif

    /*以下是正常的TCP socket建立过程*/
    printf("Begin tcp socket...\n");

#ifdef _WIN32
    	//初始化WSA
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA wsaData;

	if (WSAStartup(sockVersion, &wsaData) != 0){
		printf("WSAStartup failed.\n");
		return 0;
	}
#endif

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock == -1){
        perror("socket");
        return -1;
    }       

    struct sockaddr_in sa;
    memset (&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("10.2.5.11");   /* Server IP */
    sa.sin_port = htons(10088);          /* Server Port number */

    if(connect(sock, (struct sockaddr*) &sa, sizeof(sa)) == -1){
        perror("connect");
        return -1;
    } 

    /* TCP 链接已建立.开始 SSL 握手过程 */
    printf("Begin SSL negotiation \n");

    // /*绑定读写套接字*/
    SSL_set_fd(clientSSL, sock);
    printf("SSL_set_fd success\n");

    if(SSL_connect(clientSSL) == -1){
        ERR_print_errors_fp(stderr);
        printf("SSL_connect failed\n");
        return -1;
    }

    printf("SSL_connect success\n");

    // /*打印使用的加密套件(可选)*/
    printf("SSL connection using %s\n", SSL_get_cipher(clientSSL));

    char sendBuf[1024 * 100] = {0};
    sprintf(sendBuf, "hello, I am sslclient.");
    if(SSL_write(clientSSL, sendBuf, strlen(sendBuf)) == -1){
         ERR_print_errors_fp(stderr);
         printf("SSL_write failed\n");
         return -1;
    } 

    char recvBuf[1024 * 100] = {0};
    int readSize = SSL_read(clientSSL, recvBuf, sizeof(recvBuf)); 
    if(readSize == -1){
        ERR_print_errors_fp(stderr);
        printf("SSL_read failed\n");
        return -1;
    }

    printf("SSL_read size %d\n", readSize);
    printf("%s\n", recvBuf);

#ifdef _WIN32
	closesocket(sock);
#else
	close(sock);
#endif

    SSL_free(clientSSL);
    SSL_CTX_free(clientCTX);
    return 0;
}
