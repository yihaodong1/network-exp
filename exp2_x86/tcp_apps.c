#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>

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
	char *str = "server echoes: ";
	do{
		memset(buf, 0, 1024);
		memcpy(buf, str, strlen(str));
		ret = tcp_sock_read(csk, buf + strlen(str), 1024 - strlen(str));
		if(ret == 0)
			tcp_sock_close(csk);
		log(INFO, "tcp server recv %d: %s", ret, buf + strlen(str));
		tcp_sock_write(csk, buf, ret);
		log(INFO, "tcp server send: %s", buf);
		
	}while(ret);
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

	char *str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char send_buf[1024];
	char recv_buf[1024];
	for(int i = 0; i < 5; ++i){
		memset(send_buf, 0, 1024);
		memset(recv_buf, 0, 1024);
		memcpy(send_buf, str + i, strlen(str) - i);
		memcpy(send_buf + strlen(str) - i, str, i);
		int ret = tcp_sock_write(tsk, send_buf, strlen(send_buf));
		log(INFO, "tcp client send: %s", send_buf);
		tcp_sock_read(tsk, recv_buf, 1024);
		log(INFO, "tcp client recv: %s", recv_buf);
	}

	sleep(1);

	tcp_sock_close(tsk);

	return NULL;
}
