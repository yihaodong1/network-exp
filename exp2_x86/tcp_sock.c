#include "tcp.h"
#include "tcp_hash.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "ip.h"
#include "rtable.h"
#include "log.h"

// TCP socks should be hashed into table for later lookup: Those which
// occupy a port (either by *bind* or *connect*) should be hashed into
// bind_table, those which listen for incoming connection request should be
// hashed into listen_table, and those of established connections should
// be hashed into established_table.

struct tcp_hash_table tcp_sock_table;
#define tcp_established_sock_table	tcp_sock_table.established_table
#define tcp_listen_sock_table		tcp_sock_table.listen_table
#define tcp_bind_sock_table			tcp_sock_table.bind_table

inline void tcp_set_state(struct tcp_sock *tsk, int state)
{
	log(DEBUG, IP_FMT":%hu switch state, from %s to %s.", \
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport, \
			tcp_state_str[tsk->state], tcp_state_str[state]);
	tsk->state = state;
}

// init tcp hash table and tcp timer
void init_tcp_stack()
{
	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_established_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_listen_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_bind_sock_table[i]);

	pthread_t timer;
	pthread_create(&timer, NULL, tcp_timer_thread, NULL);
}

// allocate tcp sock, and initialize all the variables that can be determined
// now
struct tcp_sock *alloc_tcp_sock()
{
	struct tcp_sock *tsk = malloc(sizeof(struct tcp_sock));

	memset(tsk, 0, sizeof(struct tcp_sock));

	tsk->state = TCP_CLOSED;
	tsk->rcv_wnd = TCP_DEFAULT_WINDOW;

	init_list_head(&tsk->list);
	init_list_head(&tsk->listen_queue);
	init_list_head(&tsk->accept_queue);
	init_list_head(&tsk->send_buf);
	init_list_head(&tsk->rcv_ofo_buf);

	tsk->rcv_buf = alloc_ring_buffer(tsk->rcv_wnd);

	tsk->wait_connect = alloc_wait_struct();
	tsk->wait_accept = alloc_wait_struct();
	tsk->wait_recv = alloc_wait_struct();
	tsk->wait_send = alloc_wait_struct();

	pthread_mutex_init(&tsk->sk_lock, NULL);
	pthread_mutex_init(&tsk->rcv_buf_lock, NULL);
	pthread_mutex_init(&tsk->send_buf_lock, NULL);

	return tsk;
}

// release all the resources of tcp sock
//
// To make the stack run safely, each time the tcp sock is refered (e.g. hashed), 
// the ref_cnt is increased by 1. each time free_tcp_sock is called, the ref_cnt
// is decreased by 1, and release the resources practically if ref_cnt is
// decreased to zero.
void free_tcp_sock(struct tcp_sock *tsk)
{
	tsk->ref_cnt -= 1;
	if (tsk->ref_cnt == 0) {
		free_ring_buffer(tsk->rcv_buf);
		free_wait_struct(tsk->wait_connect);
		free_wait_struct(tsk->wait_accept);
		free_wait_struct(tsk->wait_recv);
		free_wait_struct(tsk->wait_send);
		free(tsk);
		log(INFO, "Do free tcp sock.");
	}
}

// lookup tcp sock in established_table with key (saddr, daddr, sport, dport)
struct tcp_sock *tcp_sock_lookup_established(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
	int value = tcp_hash_function(saddr, daddr, sport, dport);
	struct list_head *list = &tcp_established_sock_table[value];

	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, hash_list) {
		if (tsk->sk_sip == saddr && tsk->sk_dip == daddr &&
				tsk->sk_sport == sport && tsk->sk_dport == dport)
			return tsk;
	}

	return NULL;
}

// lookup tcp sock in listen_table with key (sport)
//
// In accordance with BSD socket, saddr is in the argument list, but never used.
struct tcp_sock *tcp_sock_lookup_listen(u32 saddr, u16 sport)
{
	int value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_listen_sock_table[value];

	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, hash_list) {
		if (tsk->sk_sport == sport)
			return tsk;
	}

	return NULL;
}

// lookup tcp sock in both established_table and listen_table
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb)
{
	u32 saddr = cb->daddr,
		daddr = cb->saddr;
	u16 sport = cb->dport,
		dport = cb->sport;

	struct tcp_sock *tsk = tcp_sock_lookup_established(saddr, daddr, sport, dport);
	if (!tsk)
		tsk = tcp_sock_lookup_listen(saddr, sport);

	return tsk;
}

// hash tcp sock into bind_table, using sport as the key
static int tcp_bind_hash(struct tcp_sock *tsk)
{
	int bind_hash_value = tcp_hash_function(0, 0, tsk->sk_sport, 0);
	struct list_head *list = &tcp_bind_sock_table[bind_hash_value];
	list_add_head(&tsk->bind_hash_list, list);

	tsk->ref_cnt += 1;

	return 0;
}

// unhash the tcp sock from bind_table
void tcp_bind_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->bind_hash_list)) {
		list_delete_entry(&tsk->bind_hash_list);
		free_tcp_sock(tsk);
	}
}

// lookup bind_table to check whether sport is in use
static int tcp_port_in_use(u16 sport)
{
	int value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_bind_sock_table[value];
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, bind_hash_list) {
		if (tsk->sk_sport == sport)
			return 1;
	}

	return 0;
}

// find a free port by looking up bind_table
static u16 tcp_get_port()
{
	for (u16 port = PORT_MIN; port < PORT_MAX; port++) {
		if (!tcp_port_in_use(port))
			return port;
	}

	return 0;
}

// tcp sock tries to use port as its source port
static int tcp_sock_set_sport(struct tcp_sock *tsk, u16 port)
{
	if ((port && tcp_port_in_use(port)) ||
			(!port && !(port = tcp_get_port())))
		return -1;

	tsk->sk_sport = port;

	tcp_bind_hash(tsk);

	return 0;
}

// hash tcp sock into either established_table or listen_table according to its
// TCP_STATE
int tcp_hash(struct tcp_sock *tsk)
{
	struct list_head *list;
	int hash;

	if (tsk->state == TCP_CLOSED)
		return -1;

	if (tsk->state == TCP_LISTEN) {
		hash = tcp_hash_function(0, 0, tsk->sk_sport, 0);
		list = &tcp_listen_sock_table[hash];
	}
	else {
		int hash = tcp_hash_function(tsk->sk_sip, tsk->sk_dip, \
				tsk->sk_sport, tsk->sk_dport); 
		list = &tcp_established_sock_table[hash];

		struct tcp_sock *tmp;
		list_for_each_entry(tmp, list, hash_list) {
			if (tsk->sk_sip == tmp->sk_sip &&
					tsk->sk_dip == tmp->sk_dip &&
					tsk->sk_sport == tmp->sk_sport &&
					tsk->sk_dport == tmp->sk_dport)
				return -1;
		}
	}

	list_add_head(&tsk->hash_list, list);
	tsk->ref_cnt += 1;

	return 0;
}

// unhash tcp sock from established_table or listen_table
void tcp_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->hash_list)) {
		list_delete_entry(&tsk->hash_list);
		free_tcp_sock(tsk);
	}
}

// XXX: skaddr here contains network-order variables
int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	int err = 0;

	// omit the ip address, and only bind the port
	err = tcp_sock_set_sport(tsk, ntohs(skaddr->port));

	return err;
}

// connect to the remote tcp sock specified by skaddr
//
// XXX: skaddr here contains network-order variables
// 1. initialize the four key tuple (sip, sport, dip, dport);
// 2. hash the tcp sock into bind_table;
// 3. send SYN packet, switch to TCP_SYN_SENT state, wait for the incoming
//    SYN packet by sleep on wait_connect;
// 4. if the SYN packet of the peer arrives, this function is notified, which
//    means the connection is established.
int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	u32 ip = ntohl(skaddr->ip);
	u16 port = ntohs(skaddr->port);
	rt_entry_t *rt_entry = longest_prefix_match(ip);
	if (!rt_entry) {
		log(ERROR, "no route to server");
		return -1;
	}

	tsk->sk_sip = rt_entry->iface->ip; // local ip
	int ret = tcp_sock_set_sport(tsk, 0);
	if(ret < 0){
		log(ERROR, "tcp_sock_set_sport failed.");
		return ret;
	}
	tsk->sk_dip = ip; // remote ip
	tsk->sk_dport = port; // remote port
	tsk->iss = tcp_new_iss();
	tsk->snd_nxt = tsk->iss;
	tcp_set_state(tsk, TCP_SYN_SENT);
	ret = tcp_hash(tsk);
	if(ret < 0){
		log(ERROR, "tcp_hash failed.");
		return ret;
	}
	tcp_send_control_packet(tsk, TCP_SYN );
	ret = sleep_on(tsk->wait_connect);
	if(ret < 0){
		log(ERROR, "tcp_sock_connect failed, wait_connect is dead.");
		return ret;
	}
	log(INFO, "tcp connection established.");

	return 0;
}

// set backlog (the maximum number of pending connection requst), switch the
// TCP_STATE, and hash the tcp sock into listen_table
int tcp_sock_listen(struct tcp_sock *tsk, int backlog)
{
	tsk->backlog = backlog;
	tcp_set_state(tsk, TCP_LISTEN);
	int ret = tcp_hash(tsk);
	if(ret < 0){
		log(ERROR, "tcp_hash failed.");
		return ret;
	}

	return 0;
}

// check whether the accept queue is full
inline int tcp_sock_accept_queue_full(struct tcp_sock *tsk)
{
	if (tsk->accept_backlog >= tsk->backlog) {
		log(ERROR, "tcp accept queue (%d) is full.", tsk->accept_backlog);
		return 1;
	}

	return 0;
}

// push the tcp sock into accept_queue
inline void tcp_sock_accept_enqueue(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->list))
		list_delete_entry(&tsk->list);
	list_add_tail(&tsk->list, &tsk->parent->accept_queue);
	tsk->parent->accept_backlog += 1;
}

// pop the first tcp sock of the accept_queue
inline struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk)
{
	struct tcp_sock *new_tsk = list_entry(tsk->accept_queue.next, struct tcp_sock, list);
	list_delete_entry(&new_tsk->list);
	init_list_head(&new_tsk->list);
	tsk->accept_backlog -= 1;

	return new_tsk;
}

// if accept_queue is not emtpy, pop the first tcp sock and accept it,
// otherwise, sleep on the wait_accept for the incoming connection requests
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk)
{
	while(list_empty(&tsk->accept_queue)) {
		int ret = sleep_on(tsk->wait_accept);
		if(ret < 0){
			log(ERROR, "tcp_sock_accept failed, wait_accept is dead.");
			return NULL;
		}
	}
	
	struct tcp_sock *new_tsk = tcp_sock_accept_dequeue(tsk);
	log(INFO, "tcp sock accepted, sip="IP_FMT", sport=%hu, dip="IP_FMT", dport=%hu.",
			HOST_IP_FMT_STR(new_tsk->sk_sip), new_tsk->sk_sport,
			HOST_IP_FMT_STR(new_tsk->sk_dip), new_tsk->sk_dport);
	return new_tsk;

}

// close the tcp sock, by releasing the resources, sending FIN/RST packet
// to the peer, switching TCP_STATE to closed
void tcp_sock_close(struct tcp_sock *tsk)
{
	// TODO: Releasing resources? ..
	tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
	if(tsk->state == TCP_ESTABLISHED)
		tcp_set_state(tsk, TCP_FIN_WAIT_1);
	else if(tsk->state == TCP_CLOSE_WAIT){
		tcp_set_state(tsk, TCP_LAST_ACK);
	}else{
		log(ERROR, "state error\n");
		exit(1);
	}
	// tcp_bind_unhash(tsk);
	// tcp_unhash(tsk);
}

// 返回值：0表示读到流结尾，对方关闭连接；-1表示出现错误；正值表示读取的数据长度
int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len)
{
	pthread_mutex_lock(&tsk->rcv_buf_lock);
	while(ring_buffer_empty(tsk->rcv_buf)){
		// NOTICE: at the end of trans, return 0 and break to close
		if(tsk->state == TCP_CLOSE_WAIT)
			break;
		log(INFO, "tcp_sock_read, wait for data.");
		pthread_mutex_unlock(&tsk->rcv_buf_lock);
		sleep_on(tsk->wait_recv);
		pthread_mutex_lock(&tsk->rcv_buf_lock);
	}
	int res = read_ring_buffer(tsk->rcv_buf, buf, len);
	pthread_mutex_unlock(&tsk->rcv_buf_lock);
	return res;
}
// 返回值：-1表示出现错误；正值表示写入的数据长度
int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len)
{
	
	// char packet[len + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE];
	char *packet = malloc(len + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE);
	memcpy(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE, buf, len);
	pthread_mutex_lock(&tsk->sk_lock);
	while (!tcp_tx_window_test(tsk)) {
		// 如果发送窗口不足，先释放锁，再等待wait_send信号激活
		pthread_mutex_unlock(&tsk->sk_lock);
		log(INFO, "sleep on wait_send, wait for send window.");
		sleep_on(tsk->wait_send);
		pthread_mutex_lock(&tsk->sk_lock);
	}
	tcp_send_packet(tsk, packet, len + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE);
	pthread_mutex_unlock(&tsk->sk_lock);
	return len;
}


#define TCP_MSS (ETH_FRAME_LEN - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE)

// 使用tsk->snd_una, tsk->snd_wnd, tsk->snd_nxt计算剩余窗口大小，如果大于TCP_MSS，
// 则返回1，否则返回0
int tcp_tx_window_test(struct tcp_sock *tsk)
{
	u32 snd_una = tsk->snd_una;
	u32 snd_wnd = tsk->snd_wnd;
	u32 snd_nxt = tsk->snd_nxt;

	if (snd_wnd + snd_una - snd_nxt > TCP_MSS){
		log(INFO, "tcp_tx_window_test: snd_wnd=%u, snd_una=%u, snd_nxt=%u, win size=%u",
			snd_wnd, snd_una, snd_nxt, snd_wnd + snd_una - snd_nxt);
		return 1;
	}
	else{
		log(INFO, "win full, tcp_tx_window_test: snd_wnd=%u, snd_una=%u, snd_nxt=%u, win size=%u",
			snd_wnd, snd_una, snd_nxt, snd_wnd + snd_una - snd_nxt);
		return 0;
	}
}

/*
创建send_buffer_entry加入send_buf尾部

注意上锁，后面不再强调。
*/
void tcp_send_buffer_add_packet(struct tcp_sock *tsk, char *packet, int len)
{
	pthread_mutex_lock(&tsk->send_buf_lock);
	struct send_buffer_entry *entry = malloc(sizeof(struct send_buffer_entry));
	entry->packet = malloc(len);
	memcpy(entry->packet, packet, len);
	entry->len = len;
	list_add_tail(&entry->list, &tsk->send_buf);
	pthread_mutex_unlock(&tsk->send_buf_lock);
}

/*
基于收到的ACK包，遍历发送队列，将已经接收的数据包从队列中移除

提取报文的tcp头可以使用packet_to_tcp_hdr，注意报文中的字段是大端序

注意上锁，后面不再强调。
*/
int tcp_update_send_buffer(struct tcp_sock *tsk, u32 ack)
{
	pthread_mutex_lock(&tsk->send_buf_lock);
	u8 flag = 0;
	struct send_buffer_entry *pos, *q;
	list_for_each_entry_safe(pos, q, &tsk->send_buf, list){
		struct tcphdr *tcp = packet_to_tcp_hdr(pos->packet);
		u32 seq_end = ntohl(tcp->seq) + pos->len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_HDR_SIZE(tcp);
		if(seq_end <= ack){
			list_delete_entry(&pos->list);
			init_list_head(&pos->list);
			free(pos->packet);
			free(pos);
			flag = 1;
			log(INFO, "update_send_buffer seq: %u, seq_end: %u, ack: %u", ntohl(tcp->seq), seq_end, ack);
		}else{
			// the insert order is from small to big
			// so can end early
			break;
		}
	}
	pthread_mutex_unlock(&tsk->send_buf_lock);
	return flag;
}

/*
获取重传队列第一个包，修改ack号和checksum并通过ip_send_packet发送。

注意不要更新snd_nxt之类的参数，这是一个独立的重传报文。
ip_send_packet会释放传入的指针，因而需要拷贝需要重传的报文。

注意上锁，后面不再强调。
*/
int tcp_retrans_send_buffer(struct tcp_sock *tsk)
{
	log(INFO, "retrans");
	pthread_mutex_lock(&tsk->send_buf_lock);
	if(!list_empty(&tsk->send_buf)) {
		struct send_buffer_entry *pos = list_entry(tsk->send_buf.next, struct send_buffer_entry, list);
		char *packet = malloc(pos->len);
		memcpy(packet, pos->packet, pos->len);
		ip_send_packet(packet, pos->len);
	}
	pthread_mutex_unlock(&tsk->send_buf_lock);
	return 1;
}

/*
1. 创建recv_ofo_buf_entry
2. 用list_for_each_entry_safe遍历rcv_ofo_buf，将表项插入合适的位置。
如果发现了重复数据包，则丢弃当前数据。
3. 调用tcp_move_recv_ofo_buffer执行报文上送

返回1表示rcv_nxt有变化，返回0表示没有
*/
int tcp_recv_ofo_buffer_add_packet(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	struct recv_ofo_buf_entry *pos = list_entry(tsk->rcv_ofo_buf.next, struct recv_ofo_buf_entry, list), *q;
	struct recv_ofo_buf_entry *new = malloc(sizeof(struct recv_ofo_buf_entry));
	new->seq = cb->seq;
	new->seq_end = cb->seq_end;
	new->len = cb->pl_len;
	new->packet = malloc(cb->pl_len);
	u8 flag = 0;
	memcpy(new->packet, cb->payload, cb->pl_len);
	if(list_empty(&tsk->rcv_ofo_buf)) {

		list_add_tail(&new->list, &tsk->rcv_ofo_buf);
		log(INFO, "add tail %u-%u", cb->seq, cb->seq_end);
		flag |= 1;
	}else if(cb->seq_end <= pos->seq){
		list_add_head(&new->list, &tsk->rcv_ofo_buf);
		log(INFO, "add head %u-%u", cb->seq, cb->seq_end);
		flag |= 1;
	}else{
		list_for_each_entry_safe(pos, q, &tsk->rcv_ofo_buf, list) {
			if(pos->seq == cb->seq && pos->seq_end == cb->seq_end)
				break;
			if(pos->seq_end <= cb->seq && 
				(q->seq >= cb->seq_end || &q->list == &tsk->rcv_ofo_buf)) {
				list_insert(&new->list, &pos->list, &q->list);
				log(INFO, "%u insert %u-%u  %u", pos->seq_end, cb->seq, cb->seq_end, q->seq);
				flag |= 1;
				break;
			}
		}
	}
	if(!flag){
		free(new->packet);
		free(new);
		log(INFO, "insert recv_ofo_buffer failed");
		return 0;
	}else
		return tcp_move_recv_ofo_buffer(tsk);
}

/*
遍历rcv_ofo_buf，将所有有序的（序列号等于tsk->rcv_nxt）的报文送入接收队列（tsk->rcv_buf）
更新rcv_nxt, rcv_wnd并唤醒接收线程(wait_recv)

如果接收队列已满，应当退出函数，而非等待。

返回1表示rcv_nxt有变化，返回0表示没有
*/
int tcp_move_recv_ofo_buffer(struct tcp_sock *tsk)
{
	// NOTE: no need to aquire the lock, as this func is called 
	// by tcp_recv_ofo_buffer_add_packet, and the caller already
	// acquire the lock
	u8 flag = 0;
	struct recv_ofo_buf_entry *pos, *q;
	list_for_each_entry_safe(pos, q, &tsk->rcv_ofo_buf, list) {
		pthread_mutex_lock(&tsk->rcv_buf_lock);
		if(ring_buffer_full(tsk->rcv_buf)){
			pthread_mutex_unlock(&tsk->rcv_buf_lock);
			break;
		}
		tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
		pthread_mutex_unlock(&tsk->rcv_buf_lock);
		log(INFO,"pos->seq: %u, tsk->rcv_nxt: %u", pos->seq, tsk->rcv_nxt);

		// if(pos->seq <= tsk->rcv_nxt && pos->seq_end > tsk->rcv_nxt) {
		if(pos->seq == tsk->rcv_nxt ) {
			list_delete_entry(&pos->list);
			init_list_head(&pos->list);

			pthread_mutex_lock(&tsk->rcv_buf_lock);
			write_ring_buffer(tsk->rcv_buf, pos->packet, pos->len);
			pthread_mutex_unlock(&tsk->rcv_buf_lock);

			wake_up(tsk->wait_recv);
			log(INFO, "rcv_nxt: %u", tsk->rcv_nxt);
			tsk->rcv_nxt = pos->seq_end;
			free(pos->packet);
			free(pos);
			flag = 1;
		}
	}
	return flag;
}
