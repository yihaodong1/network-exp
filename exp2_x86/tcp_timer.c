#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>
#include "log.h"

static struct list_head timer_list;
static pthread_mutex_t timer_list_lock = PTHREAD_MUTEX_INITIALIZER;

/*
1. 如果已经启用，则直接退出
2. 创建定时器，设置各个成员变量，设置timeout为比如TCP_RETRANS_INTERVAL_INITIAL
3. 增加tsk的引用计数，将定时器加入timer_list末尾
*/
void tcp_set_persist_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_list_lock);
	if(tsk->persist_timer.enable) {
		pthread_mutex_unlock(&timer_list_lock);
		return;
	}
	tsk->persist_timer.enable = 1;
	tsk->persist_timer.type = 2; // persist
	tsk->persist_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	list_add_tail(&tsk->persist_timer.list, &timer_list);
	tsk->ref_cnt += 1; // increase ref_cnt to avoid freeing the tcp sock
	log(INFO, "set persist timer");
	pthread_mutex_unlock(&timer_list_lock);
}

/*
1. 如果已经禁用，不做任何事
2. 调用free_tcp_sock减少tsk引用计数，并从链表中移除timer
*/
void tcp_unset_persist_timer(struct tcp_sock *tsk)
{
	// NOTE: no need to lock, as this fun only used
	// by tcp_time_list_scan, and tcp_time_list_scan already
	// lock!!!!

	// pthread_mutex_lock(&timer_list_lock);
	if(!tsk->persist_timer.enable) {
		// pthread_mutex_unlock(&timer_list_lock);
		return;
	}
	free_tcp_sock(tsk);
	list_delete_entry(&tsk->persist_timer.list);
	tsk->persist_timer.enable = 0;
	log(INFO, "unset persist timer");
	// pthread_mutex_unlock(&timer_list_lock);
}

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	pthread_mutex_lock(&timer_list_lock);
	struct tcp_timer *pos, *q;
	struct tcp_sock *tsk;
	list_for_each_entry_safe(pos, q, &timer_list, list) {
		if(pos->enable){
			pos->timeout -= TCP_TIMER_SCAN_INTERVAL;
			if(pos->timeout <= 0){
				switch(pos->type){
					case 0:// time-wait
						list_delete_entry(&pos->list);
						tsk = timewait_to_tcp_sock(pos);
						tcp_set_state(tsk, TCP_CLOSED);
						free_tcp_sock(tsk);
						tcp_bind_unhash(tsk);
						tcp_unhash(tsk);
						break;
					case 1:// retrans
						break;
					case 2:// persist
						pos->timeout = TCP_RETRANS_INTERVAL_INITIAL;
						tsk = persisttimer_to_tcp_sock(pos);
						if(tcp_tx_window_test(tsk) == 0) {
							tcp_send_probe_packet(tsk);
						}else{
							tcp_unset_persist_timer(tsk);
						}
						break;
				}
			}

		}
	}
	pthread_mutex_unlock(&timer_list_lock);
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_list_lock);
	if(tsk->timewait.enable) {
		pthread_mutex_unlock(&timer_list_lock);
		return;
	}
	tsk->ref_cnt += 1; // increase ref_cnt to avoid freeing the tcp sock
	tsk->timewait.enable = 1;
	tsk->timewait.type = 0; // time-wait
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
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
