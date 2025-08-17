#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include <pthread.h>
#include <fcntl.h>
#include "openssl/err.h"
char response200[] = "HTTP/1.0 200 OK\r\nContent-Length: ";
char response301[] = "HTTP/1.0 301 Moved Permanently\r\nLocation:https://10.0.0.1";
char response206[] = "HTTP/1.0 206 Partial Content\r\nContent-Length: ";
char response404[] = "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n";
void get_range(char *buf, int *start, int *end)
{
	char *line = strtok(buf, "\r\n");
	while (line) {
		if (sscanf(line, "Range: bytes=%d-%d", start, end) == 2) {
			return;
		}
		if(sscanf(line, "Range: bytes=%d-", start) == 1) {
			*end = -1;
			return;
		}
		line = strtok(NULL, "\r\n");
	}
	*start = 0;
	*end = -1;
}
void handle_https_request(SSL* ssl)
{
    if (SSL_accept(ssl) == -1){
		perror("SSL_accept failed");
		exit(1);
	}
    else {
		char buf[1024] = {0};
        int bytes = SSL_read(ssl, buf, sizeof(buf));
		if (bytes < 0) {
			perror("SSL_read failed");
			exit(1);
		}
		char method[16], path[128], protocol[16];

		sscanf(buf, "%s %s %s", method, path, protocol);

		char path1[20] = {"./dir"};
		char path2[20] = {"."};
		strcat(path1, path);
		strcat(path2, path);
		int start, end;
		get_range(buf, &start, &end);

		int fd = open(path1, O_RDONLY);
		if(fd < 0)
			fd = open(path2, O_RDONLY);
		if(fd < 0) {
			SSL_write(ssl, response404, strlen(response404));
		}else{
			size_t file_size = lseek(fd, 0, SEEK_END);
			char *buf = malloc(file_size + strlen(response200) + 100);
			size_t content_len = end == -1 ? file_size - start : end - start + 1;
			if(end == -1 && start == 0)
				sprintf(buf, "%s%zu\r\n\r\n", response200, content_len);
			else
			 	sprintf(buf, "%s%zu\r\n\r\n", response206, content_len);
			int headerlen = strlen(buf);
			lseek(fd, start, SEEK_SET);
			if(end == -1)
				read(fd, buf + headerlen, file_size - start);
			else
			 	read(fd, buf + headerlen, end - start + 1);
			SSL_write(ssl, buf, headerlen + content_len);
			free(buf);
		}
    }
    int sock = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sock);
}

void handle_http_request()
{

}

void httpfunc(int sock)
{
	while (1) {
		struct sockaddr_in caddr;
		socklen_t len;
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
		char buf[1024] = {0};
        int bytes = read(csock, buf, sizeof(buf));
		if (bytes < 0) {
			perror("read failed");
			exit(1);
		}
		char method[16], path[128], protocol[16];
		sscanf(buf, "%s %s %s", method, path, protocol);
		memset(buf, 0, sizeof(buf));
		memcpy(buf, response301, strlen(response301));
		strcat(buf, path);
		write(csock, buf, strlen(buf));
		close(csock);
	}
	close(sock);
}

void httpsfunc(int sock)
{
	// init SSL Library
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	// enable TLS method
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);

	// load certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
		perror("load cert failed");
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
		perror("load prikey failed");
		exit(1);
	}
	while (1) {
		struct sockaddr_in caddr;
		socklen_t len;
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
		SSL *ssl = SSL_new(ctx); 
		SSL_set_fd(ssl, csock);
		handle_https_request(ssl);
	}

	close(sock);
	SSL_CTX_free(ctx);
}

int bindport(int port)
{
	// init socket, listening to port
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
		exit(1);
	}
	listen(sock, 10);
	return sock;
}

int main()
{
	pthread_t tid[2];

	int sock443 = bindport(443);
	int sock80 = bindport(80);
	pthread_create(&tid[0], NULL, (void*)httpsfunc, (void*)(intptr_t)sock443);
	pthread_create(&tid[1], NULL, (void*)httpfunc, (void*)(intptr_t)sock80);
	pthread_join(tid[0], NULL);
	pthread_join(tid[1], NULL);


	return 0;
}
