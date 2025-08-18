#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
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
			
			tcp_set_state(new_tsk, TCP_SYN_RECV);
			tcp_hash(new_tsk);
			tcp_send_control_packet(new_tsk, TCP_ACK | TCP_SYN);
			return;
		}else if(tsk->state == TCP_SYN_SENT){
			if(cb->flags & TCP_ACK && cb->flags & TCP_SYN) {
				tcp_set_state(tsk, TCP_ESTABLISHED);
				wake_up(tsk->wait_connect);
				flags = TCP_ACK;
			}
		}
	}
	if(cb->flags & TCP_ACK){
		tcp_update_window_safe(tsk, cb);
		if(tsk->state == TCP_SYN_RECV){
			if(!tcp_sock_accept_queue_full(tsk->parent)){
				tcp_set_state(tsk, TCP_ESTABLISHED);
				list_delete_entry(&tsk->list);
				init_list_head(&tsk->list);
				tcp_sock_accept_enqueue(tsk);
				wake_up(tsk->parent->wait_accept);
			}
		}
		else if(tsk->state == TCP_LAST_ACK){
			tcp_set_state(tsk, TCP_CLOSED);
			tcp_unhash(tsk);
		}else if(tsk->state == TCP_FIN_WAIT_1){
			tcp_set_state(tsk, TCP_FIN_WAIT_2);
		}
	}
	
	if(cb->flags & TCP_FIN) {
		if(tsk->state == TCP_ESTABLISHED){
			flags = TCP_ACK;
			tcp_set_state(tsk, TCP_CLOSE_WAIT);
			// NOTICE: at the end of trans, wake up wait_recv and close
			wake_up(tsk->wait_recv);
		}
		else if(tsk->state == TCP_FIN_WAIT_2){
			tcp_set_timewait_timer(tsk);
			tcp_set_state(tsk, TCP_TIME_WAIT);
			flags = TCP_ACK;
		}
	}
	if(cb->payload && cb->pl_len){
		write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
		wake_up(tsk->wait_recv);
	}
	tsk->sk_sip = cb->daddr;
	tsk->sk_sport = cb->dport;
	tsk->sk_dip = cb->saddr;
	tsk->sk_dport = cb->sport;
	tsk->rcv_nxt = cb->seq_end;
	if(flags)
		tcp_send_control_packet(tsk, flags);
}
