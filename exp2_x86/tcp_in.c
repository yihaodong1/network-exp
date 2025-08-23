#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
#include <sys/time.h>

// #define __CONGESTION_CONTROL
pthread_t cwnd_record;
void pre_fastrecover(struct tcp_sock *tsk)
{
	tsk->dupACKcount = 0;
	tsk->c_state = CONG_FASTRECOVERY;
	tsk->ssthresh = tsk->cwnd / 2;
	tsk->cwnd = tsk->ssthresh + 3 * TCP_MSS;
	tsk->recovery_point = tsk->snd_nxt;
	log(INFO, "cwnd:%u, ssthresh:%u, recovery_point: %u, stay in CONG_FASTRECOVERY", 
		tsk->cwnd, tsk->ssthresh, tsk->recovery_point);
	pthread_mutex_lock(&tsk->send_buf_lock);
	if(!list_empty(&tsk->send_buf)){
		struct send_buffer_entry *pos = list_entry(tsk->send_buf.next, struct send_buffer_entry, list);
		struct tcphdr *tcp = packet_to_tcp_hdr(pos->packet);
		// tsk->snd_nxt = ntohl(tcp->seq) + pos->len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_HDR_SIZE(tcp);
		// log(INFO, "update snd_nxt: %u", tsk->snd_nxt);
	}
	pthread_mutex_unlock(&tsk->send_buf_lock);
	tcp_retrans_send_buffer(tsk);

}
/*新增tcp_congestion_control函数
 函数tcp_congestion_control根据当前TCP拥塞控制的阶段(tsk->c_state)和收到的ACK数据包信息(cb->ack和ack_valid),
 更新拥塞窗口cwnd,慢启动阈值ssthresh等参数.
它通过状态机的方式处理不同的拥塞控制阶段: OPEN, DISORDER, LOSS 和 RECOVERY
在update_window前使用
*/
void tcp_congestion_control(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	u8 ack_valid = cb->ack > tsk->snd_una && cb->ack <= tsk->snd_nxt;
	// u8 ack_dup = cb->ack <= tsk->snd_una;
	u8 ack_dup = cb->ack == tsk->snd_una;
	log(INFO, "cwnd:%u", tsk->cwnd);
	switch(tsk->c_state){
		case CONG_SLOWSTART:
			if(ack_valid){
				tsk->cwnd += TCP_MSS;
				tsk->dupACKcount = 0;
			}else if(ack_dup){
				tsk->dupACKcount++;
			}
			if(tsk->dupACKcount >= 3){
				log(INFO, "from CONG_SLOWSTART switch to CONG_FASTRECOVERY");
				pre_fastrecover(tsk);
				break;
			}
			if(tsk->cwnd > tsk->ssthresh){
				tsk->c_state = CONG_CONGAVOID;
				log(INFO, "cwnd %u > ssthresh %u, from CONG_SLOWSTART switch to CONG_CONGAVOID", tsk->cwnd, tsk->ssthresh);
			}
			break;
		case CONG_CONGAVOID:
			if(ack_valid){
				tsk->cwnd += 1;
				tsk->dupACKcount = 0;
			}else if(ack_dup){
				tsk->dupACKcount++;
			}
			if(tsk->dupACKcount >= 3){
				log(INFO, "from CONG_CONGAVOID switch to CONG_FASTRECOVERY");
				pre_fastrecover(tsk);
			}
			break;
		case CONG_FASTRECOVERY:
			if(cb->ack >= tsk->recovery_point){
				// tsk->snd_nxt = tsk->recovery_point;
				tsk->cwnd = tsk->ssthresh;
				tsk->c_state = CONG_CONGAVOID;
				log(INFO, "cwnd: %u , ssthresh: %u, \
					from CONG_FASTRECOVERY switch to CONG_CONGAVOID"
				, tsk->cwnd, tsk->ssthresh);
				break;
			}else if(ack_dup){
				tsk->cwnd += TCP_MSS;
			}else if(ack_valid){
				pthread_mutex_lock(&tsk->send_buf_lock);
				if(!list_empty(&tsk->send_buf)){
					struct send_buffer_entry *pos = list_entry(tsk->send_buf.next, struct send_buffer_entry, list);
					struct tcphdr *tcp = packet_to_tcp_hdr(pos->packet);
					// tsk->snd_nxt = ntohl(tcp->seq) + pos->len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_HDR_SIZE(tcp);
					// log(INFO, "update snd_nxt: %u", tsk->snd_nxt);
				}
				pthread_mutex_unlock(&tsk->send_buf_lock);
				tcp_retrans_send_buffer(tsk);
			}
			break;
			
	}
}

//cwnd 记录函数：
void *tcp_cwnd_thread(void *arg) {
    struct tcp_sock *tsk = (struct tcp_sock *)arg;
    FILE *fp = fopen("cwnd.txt", "w");

    u32 time_us = 0;
	struct timeval tv_last, tv_now;
	gettimeofday(&tv_last, NULL);
	do{
		gettimeofday(&tv_now, NULL);
		time_us += (tv_now.tv_sec - tv_last.tv_sec) * 1000000 + (tv_now.tv_usec - tv_last.tv_usec);
		tv_last = tv_now;
        fprintf(fp, "%u %u %u %u\n", time_us, tsk->cwnd, tsk->ssthresh, tsk->adv_wnd);
		sleep_on(tsk->wait_record);
	}while(tsk->state == TCP_ESTABLISHED && time_us < 3000000);

    // while (tsk->state == TCP_ESTABLISHED && time_us < 3000000) {
    //     usleep(100); //每500us唤醒一次，按需更改
    //     time_us += 100;
    //     fprintf(fp, "%u %u %u %u\n", time_us, tsk->cwnd, tsk->ssthresh, tsk->adv_wnd);
    // }
    fclose(fp);
    return NULL;
}

// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	int old_test_res = tcp_tx_window_test(tsk);
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->adv_wnd = cb->rwnd;
	#ifdef __CONGESTION_CONTROL
	tsk->snd_wnd = min(tsk->adv_wnd, tsk->cwnd);
	#else
	tsk->snd_wnd = tsk->adv_wnd;
	tsk->cwnd = 0x7f7f7f7f;
	#endif
	tsk->snd_una = cb->ack;
	int new_test_res = tcp_tx_window_test(tsk);
	log(INFO, "tcp_tx_win_res:%d new_res: %d", old_test_res, new_test_res);
	if(old_test_res == 0 && new_test_res == 1){
		wake_up(tsk->wait_send);
		log(INFO, "wake up wait_send");
	}
	if(new_test_res == 0){
		tcp_set_persist_timer(tsk);
	}
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	u8 flags = 0;
	if(cb->flags & TCP_RST){
		tcp_send_reset(cb);
	}
	if(cb->flags & TCP_SYN) {
		if(tsk->state == TCP_LISTEN){
		
			struct tcp_sock *new_tsk = alloc_tcp_sock();
			new_tsk->parent = tsk;
			list_add_head(&new_tsk->list, &tsk->listen_queue);
			new_tsk->sk_sip = cb->daddr; // local ip
			new_tsk->sk_sport = cb->dport; // local port
			new_tsk->sk_dip = cb->saddr; // remote ip
			new_tsk->sk_dport = cb->sport;
			new_tsk->rcv_nxt = cb->seq_end;
			new_tsk->iss = tcp_new_iss();
			new_tsk->snd_nxt = new_tsk->iss;
			new_tsk->snd_una = new_tsk->iss;
			
			tcp_set_state(new_tsk, TCP_SYN_RECV);
			tcp_hash(new_tsk);
			tcp_send_control_packet(new_tsk, TCP_ACK | TCP_SYN);
			return;
		}else if(tsk->state == TCP_SYN_SENT){
			if(cb->flags & TCP_ACK && cb->flags & TCP_SYN) {
				pthread_mutex_lock(&timer_list_lock);
				tcp_unset_retrans_timer(tsk);
				pthread_mutex_unlock(&timer_list_lock);
				tcp_set_state(tsk, TCP_ESTABLISHED);
				wake_up(tsk->wait_connect);
				tsk->rcv_nxt = cb->seq_end;// first packet
				flags = TCP_ACK;
				pthread_create(&cwnd_record, NULL, tcp_cwnd_thread, (void *)tsk);
			}
		}
	}
	if(cb->flags & TCP_ACK){
		tcp_update_send_buffer(tsk, cb->ack);
		#ifdef __CONGESTION_CONTROL
		tcp_congestion_control(tsk, cb, packet);
		wake_up(tsk->wait_record);
		#endif
		tcp_update_window_safe(tsk, cb);
		tcp_update_retrans_timer(tsk);
		if(tsk->state == TCP_SYN_RECV){
			if(!tcp_sock_accept_queue_full(tsk->parent)){
				// establish and close the retrans of syn
				pthread_mutex_lock(&timer_list_lock);
				tcp_unset_retrans_timer(tsk);
				pthread_mutex_unlock(&timer_list_lock);

				tcp_set_state(tsk, TCP_ESTABLISHED);
				list_delete_entry(&tsk->list);
				init_list_head(&tsk->list);
				tcp_sock_accept_enqueue(tsk);
				wake_up(tsk->parent->wait_accept);
			}
		}
		else if(tsk->state == TCP_LAST_ACK){
			// close the retrans of fin
			pthread_mutex_lock(&timer_list_lock);
			tcp_unset_retrans_timer(tsk);
			pthread_mutex_unlock(&timer_list_lock);

			tcp_set_state(tsk, TCP_CLOSED);
			tcp_unhash(tsk);
		}else if(tsk->state == TCP_FIN_WAIT_1 && tsk->snd_nxt == cb->ack){
			// close the retrans of fin
			pthread_mutex_lock(&timer_list_lock);
			tcp_unset_retrans_timer(tsk);
			pthread_mutex_unlock(&timer_list_lock);

			tcp_set_state(tsk, TCP_FIN_WAIT_2);
		}
	}
	
	if(cb->flags & TCP_FIN) {
		if(tsk->state == TCP_ESTABLISHED&& tsk->rcv_nxt == cb->seq){
			flags = TCP_ACK;
			tcp_set_state(tsk, TCP_CLOSE_WAIT);
			// NOTICE: at the end of trans, wake up wait_recv and close
			wake_up(tsk->wait_recv);
			if(cb->payload && cb->pl_len){
				;
			}else
				tsk->rcv_nxt += 1;
		}
		else if(tsk->state == TCP_FIN_WAIT_2){
			tcp_set_timewait_timer(tsk);
			tcp_set_state(tsk, TCP_TIME_WAIT);
			tsk->rcv_nxt += 1;
			flags = TCP_ACK;
		}
	}
	if(cb->payload && cb->pl_len){
		if(less_or_equal_32b(cb->seq_end, tsk->rcv_nxt)){
			log(INFO, "keep alive");
			flags = TCP_ACK; // keep alive
		}else{
			tcp_recv_ofo_buffer_add_packet(tsk, cb);
				flags = TCP_ACK | TCP_PSH;
			// if(tcp_recv_ofo_buffer_add_packet(tsk, cb)){
			// 	flags = TCP_ACK | TCP_PSH;
			// }
		}
	}
	tsk->sk_sip = cb->daddr;
	tsk->sk_sport = cb->dport;
	tsk->sk_dip = cb->saddr;
	tsk->sk_dport = cb->sport;
	if(flags)
		tcp_send_control_packet(tsk, flags);
}
