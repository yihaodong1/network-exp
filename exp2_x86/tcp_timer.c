#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;
static pthread_mutex_t timer_list_lock = PTHREAD_MUTEX_INITIALIZER;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	struct tcp_timer *pos, *q;
	list_for_each_entry_safe(pos, q, &timer_list, list) {
		pos->timeout += TCP_TIMER_SCAN_INTERVAL;
		if(pos->timeout >= TCP_TIMEWAIT_TIMEOUT){
			list_delete_entry(&pos->list);
			tcp_set_state(timewait_to_tcp_sock(pos), TCP_CLOSED);
			tcp_bind_unhash(timewait_to_tcp_sock(pos));
			tcp_unhash(timewait_to_tcp_sock(pos));
		}
	}
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_list_lock);
	tsk->timewait.type = 0; // time-wait
	tsk->timewait.timeout = 0;
	list_add_tail(&tsk->timewait.list, &timer_list);
	pthread_mutex_unlock(&timer_list_lock);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
