#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>
#include <fcntl.h>
// #define __SERVER_ECHO
#define __SEND_FILE

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	char buf[1024];
	int ret;
	#ifdef __SERVER_ECHO
	char *str = "server echoes: ";
	do{
		memset(buf, 0, 1024);
		memcpy(buf, str, strlen(str));
		ret = tcp_sock_read(csk, buf + strlen(str), 1024 - strlen(str));
		if(ret == 0){
			tcp_sock_close(csk);
			break;
		}
		log(INFO, "tcp server recv %d: %s", ret, buf + strlen(str));
		tcp_sock_write(csk, buf, ret);
		log(INFO, "tcp server send: %s", buf);
		
	}while(ret);
	#endif

	#ifdef __SEND_FILE
	int fd = open("server-output.dat", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	do{
		memset(buf, 0, 1000);
		ret = tcp_sock_read(csk, buf, 1000);
		// log(INFO, "server write %d", ret);
		if(ret == 0)
			tcp_sock_close(csk);
		write(fd, buf, ret);
	}while(ret);
	#endif
	// sleep(5);

	// tcp_sock_close(csk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	#ifdef __SERVER_ECHO
	char *str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char send_buf[1024];
	char recv_buf[1024];
	for(int i = 0; i < 10; ++i){
		memset(send_buf, 0, 1024);
		memset(recv_buf, 0, 1024);
		memcpy(send_buf, str + i, strlen(str) - i);
		memcpy(send_buf + strlen(str) - i, str, i);
		int ret = tcp_sock_write(tsk, send_buf, strlen(send_buf));
		log(INFO, "tcp client send: %s", send_buf);
		tcp_sock_read(tsk, recv_buf, 1024);
		log(INFO, "tcp client recv: %s", recv_buf);
	}
	#endif
	#ifdef __SEND_FILE
	// send a file
	int fd = open("client-input.dat", O_RDONLY);
	if(fd < 0){
		log(ERROR, "open client-input.dat failed");
		exit(1);
	}
	char buf[1000];
	memset(buf, 0, 1000);
	int ret;
	while((ret = read(fd, buf, 1000)) > 0){
		tcp_sock_write(tsk, buf, ret);
		memset(buf, 0, 1000);
		log(INFO, "client write %d", ret);
	}
	close(fd);
	#endif

	// sleep(1);

	tcp_sock_close(tsk);

	return NULL;
}
