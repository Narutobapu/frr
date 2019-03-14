#include <zebra.h>
#include <cetcd.h>
#include "log.h"
#include "libfrr.h"
#include "stream.h"
#include "thread.h"
#include "network.h"
#include "command.h"
#include "version.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_fpm_private.h"
#include "fpm/fpm.h"
#include "lib/prefix.h"

/*
 *  * Interval at which we attempt to connect to the ETCD.
 *   */
#define ZETCD_CONNECT_RETRY_IVL   5

/*
 *  * Sizes of outgoing and incoming stream buffers for writing/reading
 *   * FPM messages.
 *    */
#define ZETCD_OBUF_SIZE (2 * ETCD_MAX_MSG_LEN)
#define ZETCD_IBUF_SIZE (ETCD_MAX_MSG_LEN)

/*
 *  * The maximum number of times the FPM socket write callback can call
 *   * 'write' before it yields.
 *    */
#define ZETCD_MAX_WRITES_PER_RUN 10

/*
 *  * Interval over which we collect statistics.
 *   */
#define ETCD_STATS_IVL_SECS        10
#define ZETCD_DEFAULT_PORT 2379
#define ZETCD_DEFAULT_IP   "127.0.0.1"
/*
 *  * Structure that holds state for iterating over all route_node
 *   * structures that are candidates for being sent to the ETCD.
 *    */
typedef struct zetcd_rnodes_iter_t_ {
    rib_tables_iter_t tables_iter;
      route_table_iter_t iter;
} zetcd_rnodes_iter_t;

/*
 * Globals.
 */
typedef struct zetcd_glob_t_ {

  bool is_connected;

  struct thread_master *master;

  char zetcd_server[32];
  /*
   * Port on which the FPM is running.
   */
  int etcd_port;
  cetcd_client zetcd_client;
  cetcd_array zetcd_addrs;
  /*
   * List of rib_dest_t structures to be processed
   */
  TAILQ_HEAD(zetcd_dest_q, rib_dest_t_) dest_q;
  /*
   * Threads for timer.
   */
  struct thread *t_connect;
  struct thread *t_push;
  /*
   * Thread to take actions once the TCP conn to the FPM comes up, and
   * the state that belongs to it.
   */
  struct thread *t_conn_up;

  struct {
    zetcd_rnodes_iter_t iter;
  } t_conn_up_state;

  struct stream *obuf;

}zetcd_glob_t;

static zetcd_glob_t zetcd_global_space;
static zetcd_glob_t *zetcd_glob_p = &zetcd_global_space;

static void zetcd_rnodes_iter_init(zetcd_rnodes_iter_t *iter)
{
  memset(iter, 0, sizeof(zetcd_rnodes_iter_t));
  rib_tables_iter_init(&iter->tables_iter);
  route_table_iter_init(&iter->iter, NULL);
  route_table_iter_cleanup(&iter->iter);
}
static inline struct route_node *zetcd_rnodes_iter_next(zetcd_rnodes_iter_t *iter)
{
  struct route_node *rn;
  struct route_table *table;

  while (1) {
    rn = route_table_iter_next(&iter->iter);
    if (rn)
      return rn;

    route_table_iter_cleanup(&iter->iter);

    table = rib_tables_iter_next(&iter->tables_iter);

    if (!table)
      return NULL;

    route_table_iter_init(&iter->iter, table);
  }
  return NULL;
}
static inline int zetcd_encode_route(rib_dest_t *dest, struct route_entry *re,
                char *in_buf, size_t in_buf_len)
{
  size_t len;
  len = zfpm_protobuf_encode_route(dest, re, (uint8_t *)in_buf,
      in_buf_len);
  return len;
}

static void zetcd_build_updates(void)
{
  struct stream *s;
  rib_dest_t *dest;
  unsigned char *buf, *data, *buf_end;
  size_t msg_len;
  size_t data_len;
  struct route_entry *re;
  int  write_msg;

  s = zetcd_glob_p->obuf;

  assert(stream_empty(s));

  do {

    if (STREAM_WRITEABLE(s) < FPM_MAX_MSG_LEN)
      break;

    buf = STREAM_DATA(s) + stream_get_endp(s);
    buf_end = buf + STREAM_WRITEABLE(s);

    dest = TAILQ_FIRST(&zetcd_glob_p->dest_q);
    if (!dest)
      break;
    data = buf;

    re = zfpm_route_for_update(dest);

    write_msg = 1;

    if (write_msg) {
      data_len = zetcd_encode_route(dest, re, (char *)data,
          buf_end - data);

      assert(data_len);
      if (data_len) {
        msg_len = (data_len);
        stream_forward_endp(s, msg_len);
      }
    }
    TAILQ_REMOVE(&zetcd_glob_p->dest_q, dest, etcd_q_entries);
  }while (0);
}
static int zetcd_push_routes_cb(struct thread *thread)
{
  struct stream *s;
  char *key = NULL;

  struct prefix *prefix = NULL;
  rib_dest_t *dest = NULL;

  cetcd_response *resp = NULL;
  int prefix_len,num_writes;

  zetcd_glob_p->t_push = NULL;
  do {
    
    s = zetcd_glob_p->obuf;
    dest = TAILQ_FIRST(&zetcd_glob_p->dest_q);
    prefix = rib_dest_prefix(dest);
    prefix_len = (prefix->prefixlen + 7)/8;
    key = malloc(prefix_len);
    memcpy(key, &prefix->u.prefix, prefix_len);
    if (stream_empty(s)) {
      zetcd_build_updates();
    }
    resp = cetcd_set(&zetcd_glob_p->zetcd_client, "/sample1", (const char *)stream_pnt(s), 1000);
    if(resp->err) 
    {
      zlog_err("error :%d, %s (%s)\n", resp->err->ecode, resp->err->message, resp->err->cause);
      cetcd_response_print(resp);
      cetcd_response_release(resp);
      break;
    }
    cetcd_response_print(resp);
    cetcd_response_release(resp);
    num_writes += 1;
    stream_reset(s);

    if (num_writes >= ZETCD_MAX_WRITES_PER_RUN) {
      break;
    }
    if (thread_should_yield(thread)) {
      break;
    }

  }while(1);
  free(key);
  return 0;
}
static inline void zetcd_push_routes()
{
  thread_add_timer_msec(zetcd_glob_p->master, zetcd_push_routes_cb, NULL, 0,
      &zetcd_glob_p->t_push);

}
static void zetcd_trigger_update(struct route_node *rn, const char *reason)
{
  rib_dest_t *dest;

  dest = rib_dest_from_rnode(rn);
  TAILQ_INSERT_TAIL(&zetcd_glob_p->dest_q, dest, etcd_q_entries);
  zetcd_push_routes();
}

static int zetcd_conn_up_thread_cb(struct thread *thread)
{
  struct route_node *rnode;
  zetcd_rnodes_iter_t *iter;
  rib_dest_t *dest;

  zetcd_glob_p->t_conn_up = NULL;

  iter = &zetcd_glob_p->t_conn_up_state.iter;
  while ((rnode = zetcd_rnodes_iter_next(iter))){
    dest = rib_dest_from_rnode(rnode);
    if (dest){
      zetcd_trigger_update(rnode,NULL);
    }
  }
  return 0;
}

static void zetcd_connection_up(const char *reason)
{
  assert(&zetcd_glob_p->zetcd_client);
  assert(!zetcd_glob_p->t_conn_up);
  zetcd_rnodes_iter_init(&zetcd_glob_p->t_conn_up_state.iter);
  thread_add_timer_msec(zetcd_glob_p->master, zetcd_conn_up_thread_cb, NULL, 0,
            &zetcd_glob_p->t_conn_up);

}
static int zetcd_connect_cb(struct thread *t)
{
  const char *zetcd_address = "http://127.0.0.1:2379";
  cetcd_response *resp = NULL;
  cetcd_array_init(&zetcd_glob_p->zetcd_addrs, 1);
  cetcd_array_append(&zetcd_glob_p->zetcd_addrs, (void *)(zetcd_address));
  cetcd_client_init(&zetcd_glob_p->zetcd_client, &zetcd_glob_p->zetcd_addrs);
  resp = cetcd_set(&zetcd_glob_p->zetcd_client, "/frr_sample", "10.40.10.10.1", 100);
  if(resp->err) 
  {
        zlog_err("error :%d, %s (%s)\n", resp->err->ecode, resp->err->message, resp->err->cause);
        cetcd_response_release(resp);
        return -1;
  }
  cetcd_response_print(resp);
  cetcd_response_release(resp);
  resp = cetcd_get(&zetcd_glob_p->zetcd_client, "/frr_sample");
  if(resp->err) 
  {
        zlog_err("error :%d, %s (%s)\n", resp->err->ecode, resp->err->message, resp->err->cause);
        cetcd_response_release(resp);
        return -1;
  }
  cetcd_response_print(resp);
  cetcd_response_release(resp);
  zetcd_glob_p->is_connected = true;
  zetcd_connection_up("connection successful");
  return 0;
}

static void zetcd_start_connect_timer(void)
{
  assert(!zetcd_glob_p->t_connect);
  assert(!zetcd_glob_p->is_connected);
  thread_add_timer(zetcd_glob_p->master, zetcd_connect_cb, 0, 10,
     &zetcd_glob_p->t_connect);
}
static int zetcd_init(struct thread_master *master)
{
  memset(zetcd_glob_p, 0, sizeof(zetcd_glob_t));
  zetcd_glob_p->master = master;
  TAILQ_INIT(&zetcd_glob_p->dest_q);
  zetcd_glob_p->etcd_port = ZETCD_DEFAULT_PORT;
  memcpy(zetcd_glob_p->zetcd_server, ZETCD_DEFAULT_IP, 32);
  zetcd_glob_p->is_connected = false;
  zetcd_glob_p->obuf = stream_new(2 * 4096);
  zetcd_start_connect_timer();
  return 0;
}

static int zebra_etcd_module_init(void)
{
  hook_register(frr_late_init, zetcd_init);
  return 0;
}

FRR_MODULE_SETUP(.name = "zebra_etcd", .version = FRR_VERSION,
     .description = "zebra etcd module",
     .init = zebra_etcd_module_init, )
