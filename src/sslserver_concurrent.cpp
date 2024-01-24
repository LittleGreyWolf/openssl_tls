/*
* 参考:https://www.cnblogs.com/stlong/p/6289142.html
*/

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string>

#ifdef _WIN32
#include <WinSock2.h>
#include <windows.h>
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

//是否校验客户端证书
//#define LOAD_CLIENT_CERT

// 业务处理函数
void disposeFunc(int *csocket, fd_set *rdset, SSL_CTX* sCTX);
// http格式数据响应
void setHttpResponse(std::string &response);

int main(){
    SSL_CTX* ServerCTX = NULL;

    SSL_load_error_strings();
    SSL_library_init();

    ServerCTX = SSL_CTX_new(TLSv1_2_server_method());
    if(ServerCTX == NULL) {
        printf("SSL_CTX_new failed.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }


    printf("SSL_CTX_new success!\n");

#ifdef _WIN32
	char cExeName[256] = {0};
	GetModuleFileName(NULL, cExeName, sizeof(cExeName) - 1);
	std::string strExeName(cExeName); 
	std::string strExeNamePath;
	strExeNamePath = strExeName.substr(0, strExeName.rfind("\\"));
#endif


#if defined(LOAD_CLIENT_CERT)
    SSL_CTX_set_verify(ServerCTX,SSL_VERIFY_PEER,NULL);   /*验证与否*/
#endif

#if defined(_WIN32) && defined(LOAD_CLIENT_CERT) 
    std::string caCertName = strExeNamePath + "\\ca.crt";
    SSL_CTX_load_verify_locations(ServerCTX, caCertName.c_str(), NULL); /*若验证,则放置CA证书*/
#elif defined(LOAD_CLIENT_CERT)
    SSL_CTX_load_verify_locations(ServerCTX,"./ca.crt",NULL);
#endif

#ifdef _WIN32
    std::string serverCertName = strExeNamePath + "\\server.crt";
    if (SSL_CTX_use_certificate_file(ServerCTX, serverCertName.c_str(), SSL_FILETYPE_PEM) <= 0) {
        printf("SSL_CTX_use_certificate_file failed.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
#else
    if (SSL_CTX_use_certificate_file(ServerCTX, "./server.crt", SSL_FILETYPE_PEM) <= 0) {
        printf("SSL_CTX_use_certificate_file failed.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
#endif

#ifdef _WIN32
    std::string serverKeyName = strExeNamePath + "\\server.key";
    if (SSL_CTX_use_PrivateKey_file(ServerCTX, serverKeyName.c_str(), SSL_FILETYPE_PEM) <= 0) {
        printf("SSL_CTX_use_PrivateKey_file failed.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
#else
    if (SSL_CTX_use_PrivateKey_file(ServerCTX, "./server.key", SSL_FILETYPE_PEM) <= 0) {
        printf("SSL_CTX_use_PrivateKey_file failed.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
#endif

    if (!SSL_CTX_check_private_key(ServerCTX)) {
       printf("Private key does not match the certificate public key\n");
       ERR_print_errors_fp(stderr);
       return -1;
    }

    SSL_CTX_set_cipher_list(ServerCTX, "ALL");

    printf("Begin TCP socket...\n");

#ifdef _WIN32
    	//初始化WSA
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA wsaData;

	if (WSAStartup(sockVersion, &wsaData) != 0)
	{
		printf("WSAStartup failed.\n");
		return 0;
	}
#endif

    int listenSock = socket(AF_INET, SOCK_STREAM, 0);  
    if(listenSock == -1){
        perror("socket");
        return -1;
    }

    struct sockaddr_in sa_serv;
    memset (&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port = htons(10088);         

    if(bind(listenSock, (struct sockaddr*) &sa_serv, sizeof (sa_serv)) == -1){
        perror("bind");
        return -1;
    }

    /*接受TCP链接*/
    if(listen(listenSock, 5) == -1){
        perror("listen");
        return -1;
    }                   

    struct sockaddr_in sa_cli;
#ifdef _WIN32
    int client_len = sizeof(sa_cli);
#else
    socklen_t client_len = sizeof(sa_cli);
#endif

    // 将监听的fd的状态检测委托给内核检测
    int maxfd = listenSock;
    // 初始化检测的读集合
    fd_set rdset;
    fd_set rdtemp;
    // 清零
    FD_ZERO(&rdset);
    // 将监听的lfd设置到检测的读集合中
    FD_SET(listenSock, &rdset);

    while(1){
        rdtemp = rdset;
        int num = select(maxfd + 1, &rdtemp, NULL, NULL, NULL);
        if (FD_ISSET(listenSock, &rdtemp)) {
            // 接受连接请求, 这个调用不阻塞
            int connfd = accept(listenSock, (struct sockaddr*) &sa_cli, &client_len);
            if(connfd == -1){
                perror("accept");
#ifdef _WIN32
                closesocket(listenSock);
#else
                close (listenSock);
#endif 
                continue;
            }
            printf("[%s:%d] client connect...\n", inet_ntoa(sa_cli.sin_addr), sa_cli.sin_port);

            // 得到了有效的文件描述符
            // 通信的文件描述符添加到读集合
            // 在下一轮select检测的时候, 就能得到缓冲区的状态
            FD_SET(connfd, &rdset);
            // 重置最大的文件描述符
            maxfd = connfd > maxfd ? connfd : maxfd;
        }

        // 没有新连接, 通信
        for (int i = 0; i < maxfd + 1; ++i) {
            // 判断从监听的文件描述符之后到maxfd这个范围内的文件描述符是否读缓冲区有数据
            if (i != listenSock && FD_ISSET(i, &rdtemp)) {
				disposeFunc((int *)&i, &rdset, ServerCTX);
            }
        }
    }

#ifdef _WIN32
	closesocket(listenSock);
#else
	close (listenSock);
#endif
    SSL_CTX_free(ServerCTX);
    return 0;
}

void disposeFunc(int *csocket, fd_set *rdset, SSL_CTX* sCTX){
    SSL* ServerSSL = SSL_new(sCTX);
    if(ServerSSL == NULL){
        printf("SSL_new failed.\n");
        ERR_print_errors_fp(stderr);
        FD_CLR(*csocket, rdset);
#ifdef _WIN32
	    closesocket(*csocket);
#else
	    close(*csocket);
#endif
        return;
    }

    SSL_set_fd(ServerSSL, *csocket);

    int sslSock = SSL_accept(ServerSSL);
    if(sslSock == -1){
        printf("SSL_accept failed.\n");
        ERR_print_errors_fp(stderr);
        FD_CLR(*csocket, rdset);
#ifdef _WIN32
	    closesocket(*csocket);
#else
	    close(*csocket);
#endif
        SSL_free(ServerSSL);
        return;
    }


    /*打印所有加密算法的信息(可选)*/
    printf ("SSL connection using %s\n", SSL_get_cipher(ServerSSL)); 
	
	char recvBuf[1024 * 100] = {0};  
	/* 数据交换开始,用SSL_write,SSL_read代替write,read */
	int readSize = SSL_read(ServerSSL, recvBuf, sizeof(recvBuf));  
	if(readSize == -1){
        printf("SSL_read failed.\n");
		ERR_print_errors_fp(stderr);
        FD_CLR(*csocket, rdset);
#ifdef _WIN32
	    closesocket(*csocket);
#else
	    close(*csocket);
#endif
        SSL_free(ServerSSL);
		return;
	}

    printf("SSL_read size = %d\n", strlen(recvBuf));
	printf("%s\n", recvBuf);

	std::string strResponse;
	setHttpResponse(strResponse);
	if(SSL_write(ServerSSL, strResponse.c_str(), strResponse.size()) == -1){
        printf("SSL_write failed.\n");
		ERR_print_errors_fp(stderr);
        FD_CLR(*csocket, rdset);
#ifdef _WIN32
	    closesocket(*csocket);
#else
	    close(*csocket);
#endif
        SSL_free(ServerSSL);
		return;
	} 

    FD_CLR(*csocket, rdset);
#ifdef _WIN32
	closesocket(*csocket);
#else
	close(*csocket);
#endif
    SSL_free(ServerSSL);
}


void setHttpResponse(std::string &response){
	response.append("HTTP/1.1 200 OK\r\n");
	response.append("Server: 10.2.5.41\r\n");
	response.append("Content-Type: text/html\r\n");
	response.append("Connection: keep-alive\r\n");
	response.append("Accept-Ranges: bytes\r\n");
	response.append("Content-Length: 163\r\n");
	
	response.append("\r\n");
	response.append("<!DOCTYPE html>\r\n");
	response.append("<html>\r\n");
	response.append("<head>\r\n");
	response.append("<meta charset=\"utf-8\">\r\n");
	response.append("<title>SCP</title>\r\n");
	response.append("</head>\r\n");
	response.append("<body>\r\n");
	response.append("<h1>hello! welcome!</h1>\r\n");
	response.append("<h2>This is test web! </h2>\r\n");
	response.append("</body>\r\n");
	response.append("</html>\r\n");
}