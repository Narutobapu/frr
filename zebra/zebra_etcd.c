#include <zebra.h>
#include <arpa/inet.h>
#include "etcd_client_txn_wrapper.h"
#include "etcd_client_wrapper.h"
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
#define ZETCD_CONNECT_RETRY_ATTEMPT   5

/*
 *  * Sizes of outgoing and incoming stream buffers for writing/reading
 *   * ETCD messages.
 *    */
#define ETCD_MAX_MSG_LEN 4096
#define ZETCD_OBUF_SIZE (2 * ETCD_MAX_MSG_LEN)


#define ETCD_STATS_IVL_SECS        10
#define ZETCD_DEFAULT_PORT "2379"
#define ZETCD_DEFAULT_IP   "127.0.0.1"
#define ZETCD_URI_MAX_LENGTH 32
#define ZETCD_MAX_TXN_PER_PUSH 5
/*
 *  * Structure that holds state for iterating over all route_node
 *   * structures that are candidates for being sent to the ETCD.
 *    */
typedef struct zetcd_rnodes_iter_t_ {

  /*
   *  * Iterator object that holds state for iterating over all tables in the
   *   * Routing Information Base.
   *    */
  rib_tables_iter_t tables_iter;

  /* * Iterator object holds state for iterating over a route table.
   * */
  route_table_iter_t iter;
} zetcd_rnodes_iter_t;

/*
 * Globals.
 */
typedef struct zetcd_glob_t_ {

  /*
   * Flag to set once connection is up.
   */
  bool is_connected;

  /*
   * master thread of all threads.
   */
  struct thread_master *master;

  /*
   * counter for connection retrial.
   */
  unsigned int conn_retries;

  /*
   * URI to connect to etcd server.
   */
  char zetcd_server[ZETCD_URI_MAX_LENGTH];
  /*
   * Port on which the ETCD is running.
   */
  int etcd_port;

  /*
   * pointer to txn add,put,delete request and response object.
   */
  txn_wrapper_t *txn_put_req;
  txn_wrapper_t *txn_get_req;
  txn_wrapper_t *txn_del_req;
  txn_wrapper_t *txn_res;

  channel_wrapper_t *channel;

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
   * Thread to take actions once the conn to the ETCD comes up, and
   * the state that belongs to it.
   */
  struct thread *t_conn_up;

  struct {
    zetcd_rnodes_iter_t iter;
  } t_conn_up_state;

  /*
   * Buffer to store protobuf encoded route entries.
   */
  struct stream *obuf;

}zetcd_glob_t;

/*Global object and pointer to etcd parameters.*/
static zetcd_glob_t zetcd_global_space;
static zetcd_glob_t *zetcd_glob_p = &zetcd_global_space;

static void zetcd_start_connect_timer(const char *reason);
/**
 * is_zetcd_connection_up
 *
 * function to check the connection.
 * */
static inline bool is_zetcd_connection_up()
{
  return zetcd_glob_p->is_connected;
}

/**
 * zetcd_rnodes_iter_init
 *
 * Initialization of route nodes iterator for etcd.
 * */
static void zetcd_rnodes_iter_init(zetcd_rnodes_iter_t *iter)
{
  memset(iter, 0, sizeof(zetcd_rnodes_iter_t));
  rib_tables_iter_init(&iter->tables_iter);
  route_table_iter_init(&iter->iter, NULL);
  route_table_iter_cleanup(&iter->iter);
}
/**
 * zetcd_rnodes_iter_next
 *
 * route table iterator for etcd module.
 * */
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
/**
 * zetcd_encode_route
 *
 * Use the zfpm_protobuf_encode_route function of fpm module to exploit the
 * logic of encoding route entry in protobuf by fpm module.
 *
 * @param[in] dest rib_dest_t type pointer.
 * @param[in] re type of route entry.
 * @param[in] in_buf pointer of buffer from where the encoded entry to write
 * into.
 *
 * Returns len length of ptotobuf encoded buffer.
 * */
static inline int zetcd_encode_route(rib_dest_t *dest, struct route_entry *re,
                char *in_buf, size_t in_buf_len)
{
  size_t len;
  len = zfpm_protobuf_encode_route(dest, re, (uint8_t *)in_buf,
      in_buf_len);
  return len;
}
/**
 * destroy_txn_context
 *
 * Destroy the objects of tranaction request and response using wrappers.
 * */
static void destroy_txn_context()
{
  destroy_txn_req_object(zetcd_glob_p->txn_put_req);
  destroy_txn_req_object(zetcd_glob_p->txn_get_req);
  destroy_txn_req_object(zetcd_glob_p->txn_del_req);

  destroy_txn_req_object(zetcd_glob_p->txn_res);
}
/**
 * create_txn_context
 *
 * creates an obect of put,get and delete transaction request and 
 * transaction response using wrappers.
 * */
static void create_txn_context()
{
  zetcd_glob_p->txn_put_req = create_txn_req_object();
  zetcd_glob_p->txn_get_req = create_txn_req_object();
  zetcd_glob_p->txn_del_req = create_txn_req_object();

  zetcd_glob_p->txn_res = create_txn_res_object();
}
static void cleanup_before_destroying_channel()
{
  /*TODO: destroy the current txn and channel context.*/
  return;
}
/**
 * create_grpc_channel_
 *
 * Create a grpc channel with given URI.
 *
 * @param[in] uri URI in format (IP:port).
 * @param[in] channel global pointer storing address of grpc channel object.
 * */
static void create_grpc_channel_(char *uri)
{
  /*Check if already a channel exist.*/
  if (zetcd_glob_p->channel)
  {
    cleanup_before_destroying_channel();
  }
  zetcd_glob_p->channel = create_grpc_channel_wrapper(uri);
  return;
}

/* Configure etcd connection parameters.*/
DEFUN(etcd_remote_ip,
       etcd_remote_ip_cmd,
       "etcd connection ip A.B.C.D port (1-65535)",
       "etcd\n"
       "connection parameters\n"
       "IP\n"
       "Remote etcd server ip A.B.C.D\n"
       "port"
       "Remote etcd server port (1-65535)\n")
{
  sprintf(zetcd_glob_p->zetcd_server,"%s:%s",argv[3]->arg,argv[5]->arg);
  zlog_debug("etcd remote connection URI:%s",zetcd_glob_p->zetcd_server);

  create_grpc_channel_(zetcd_glob_p->zetcd_server);
  zetcd_glob_p->etcd_port = atoi(argv[5]->arg);
  return CMD_SUCCESS;
}
/**
 * zetcd_build_updates
 *
 * Process the route entries and encode them into protobuf.
 *
 * */
static void zetcd_build_updates(void)
{
  struct stream *s;
  rib_dest_t *dest;
  unsigned char *buf, *data, *buf_end;
  size_t msg_len;
  size_t data_len;
  struct route_entry *re;

  /*Get the buffer pointer where protobuf encoded entry to be stored.*/
  s = zetcd_glob_p->obuf;

  assert(stream_empty(s));
  /*Check available buffer is enough.*/
  if (STREAM_WRITEABLE(s) < FPM_MAX_MSG_LEN)
    return;

  buf = STREAM_DATA(s) + stream_get_endp(s);
  buf_end = buf + STREAM_WRITEABLE(s);

  dest = TAILQ_FIRST(&zetcd_glob_p->dest_q);
  if (!dest)
    return;
  data = buf;

  /*Route entry type.*/
  re = zfpm_route_for_update(dest);

  /* Protobuf encode the route entry information and return length of resulted 
   * buffer.*/
  data_len = zetcd_encode_route(dest, re, (char *)data,
      buf_end - data);

  assert(data_len);
  if (data_len) {
    msg_len = (data_len);
    stream_forward_endp(s, msg_len);
  }
  else
    return;
  /*Remove the route entry pointer from dest_q of etcd once processed.*/
  TAILQ_REMOVE(&zetcd_glob_p->dest_q, dest, etcd_q_entries);
}
/**
 * etcd_txn
 *
 * Request the transaction to channel.
 * 
 * Return TRUE if success, else FALSE.
 * */
static int etcd_txn(txn_wrapper_t *txn_req)
{
  /*calls wrapper function.*/
  return (txn_wrapper(zetcd_glob_p->channel->obj, zetcd_glob_p->txn_res->obj,
      txn_req->obj));
}

/**
 * zetcd_push_routes_cb
 *
 * Dequeue the route nodes from etcd dest_q, fetches the important route 
 * information from an entry. Protobuf encode the route information and push it
 * to etcd.
 *
 * @param[in] prefix pointer to prefix structure storing route IP prefix.
 * @param[in] selected_fib best selected forwarding option from available
 * choices for particular IP prefix.
 * */
static int zetcd_push_routes_cb(struct thread *thread)
{
  struct stream *s = NULL;
  char *key = NULL;
  char *value = NULL;
  int ret = 0;
  struct prefix *prefix = NULL;
  rib_dest_t *dest = NULL;
  bool recursive = false;
  int len = 0;
  /*unsigned int num_writes = 0;
  bool is_put_txn_pending = false;
  bool is_del_txn_pending = false;
  txn_wrapper_t *txn_req = NULL;*/

  zetcd_glob_p->t_push = NULL;
  do {
    
    s = zetcd_glob_p->obuf;

    /*Retreive route entries from queue.*/
    dest = TAILQ_FIRST(&zetcd_glob_p->dest_q);
    if (dest->rnode)
    {
      /*Get route's IP prefix and use it as key to etcd keyspace.*/
      prefix = rib_dest_prefix(dest);
      key = inet_ntoa(prefix->u.prefix4);
    }
    /*If there are no processed pending route entries, then process one.*/
    if (stream_empty(s)) {
      zetcd_build_updates();
    }
    /*Get the pointer to protobuf encoded route entry and calculate its length.*/
    value = (char *)stream_pnt(s);
    len = stream_get_endp(s) - stream_get_getp(s);
    /*check if entry is processed.*/
    if (!len)
    {
      zlog_warn("Unable to process route entry with prefix:%s",key);
      return 0;
    }
    /*FIXME:creating txn for every route entry isn't efficient.*/
    create_txn_context();
    /*Check if the entry is added or deleted.*/
    if (!dest->selected_fib)
    {
      //if (is_put_txn_pending)
       // break;
      zetcd_glob_p->txn_del_req = create_del_txn(key, recursive,
          zetcd_glob_p->txn_del_req);
      //is_del_txn_pending = true;

      ret = etcd_txn(zetcd_glob_p->txn_del_req);
      if(ret)
      {
        zlog_err("error Unable to push into etcd");
        /*TODO: check the status and take action accordingly.*/
        continue;
      }
    }
    else
    {
      //if (is_del_txn_pending)
       // break;
      zetcd_glob_p->txn_put_req = create_put_txn(key, value, len,
          zetcd_glob_p->txn_put_req);
      //is_put_txn_pending = true;
      ret = etcd_txn(zetcd_glob_p->txn_put_req);
      if(ret)
      {
        zlog_err("error Unable to push into etcd");
        continue;
      }
    }
    destroy_txn_context();
    //if (num_writes++ > ZETCD_MAX_TXN_PER_PUSH)
    // break; 
    stream_reset(s);
    UNSET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
  }while(TAILQ_FIRST(&zetcd_glob_p->dest_q));

#if 0
  /*Send it to etcd keyspace via grpc channel.*/
  if (is_put_txn_pending)
    txn_req = zetcd_glob_p->txn_put_req;
  else if(is_del_txn_pending)
    txn_req = zetcd_glob_p->txn_del_req;
  else
    return 0;
  is_put_txn_pending = false;
  is_del_txn_pending = false;
#endif 
  return 0;
}

/**
 * zetcd_push_routes
 *
 * Schedule a task zetcd_push_routes_cb to encode and push routes.
 *
 * */
static inline void zetcd_push_routes()
{
  thread_add_timer_msec(zetcd_glob_p->master, zetcd_push_routes_cb, NULL, 0,
      &zetcd_glob_p->t_push);

}
/**
 * zetcd_trigger_update
 *
 * Insert the updated route node to the dest_q buffer of etcd module. Skip the
 * route information if already under process.
 *
 * */
static int zetcd_trigger_update(struct route_node *rn, const char *reason)
{
  rib_dest_t *dest;

  if (!is_zetcd_connection_up())
    return 0;

  dest = rib_dest_from_rnode(rn);

  /*Skip redundant entry.*/
  if (CHECK_FLAG(dest->flags, RIB_DEST_UPDATE_FPM)) {
    return 0;
  }
  SET_FLAG(dest->flags, RIB_DEST_UPDATE_FPM);
  TAILQ_INSERT_TAIL(&zetcd_glob_p->dest_q, dest, etcd_q_entries);
  zetcd_push_routes();
  return 0;
}
/**
 * zetcd_conn_up_thread_cb
 * 
 * Process the iterator, with each route node triggered to sent to etcd.
 *
 * @param[in] iter iterator of route nodes.
 * @param[in] dest pointer to route information unit having pointers to nodes.
 * @param[in] rnode a pointer to one route node.
 * */
static int zetcd_conn_up_thread_cb(struct thread *thread)
{
  struct route_node *rnode = NULL;
  zetcd_rnodes_iter_t *iter = NULL;
  rib_dest_t *dest = NULL;

  zetcd_glob_p->t_conn_up = NULL;

  iter = &zetcd_glob_p->t_conn_up_state.iter;
  /*Iterate over route nodes and trigger update for each entry.*/
  while ((rnode = zetcd_rnodes_iter_next(iter))){
    dest = rib_dest_from_rnode(rnode);
    if (dest){
      zetcd_trigger_update(rnode,NULL);
    }
  }
  return 0;
}
/**
 * zetcd_connection_up
 *
 * After establishing connection initialize the route node iterator and add 
 * task zetcd_conn_up_thread_cb in timer thread to process the route nodes.
 *
 * */
static void zetcd_connection_up(const char *reason)
{
  assert(&zetcd_glob_p->channel);
  assert(!zetcd_glob_p->t_conn_up);
  zetcd_rnodes_iter_init(&zetcd_glob_p->t_conn_up_state.iter);
  thread_add_timer_msec(zetcd_glob_p->master, zetcd_conn_up_thread_cb, NULL, 0,
            &zetcd_glob_p->t_conn_up);
}

/**
 * zetcd_connect_cb
 * 
 * create a grpc channel and put and delete a sample to check connectivity. If
 * connectivity failed try to reconnect. If unable to connect after
 * ZETCD_CONNECT_RETRY_ATTEMPT then abort.
 * 
 * @param[in] txn_put_req a pointer to etcd put transaction request object.
 * @param[in] txn_del_req a pointer to etcd delete transaction request object.
 * 
 * */

static int zetcd_connect_cb(struct thread *t)
{
  int ret;

  /*Check if already connected.*/
  if (zetcd_glob_p->is_connected)
    return 0;

  /*Check if max attempt exceeded.*/
  if (zetcd_glob_p->conn_retries > ZETCD_CONNECT_RETRY_ATTEMPT)
  {
    zlog_warn("Max attempt to connect to etcd server exceeded.");
    return -1;
  }

  /* Create sample put object.*/
  create_put_txn("sample","test",10,zetcd_glob_p->txn_put_req);

  /*Create grpc channel using wrapper function with zetcd_server URI.*/
	create_grpc_channel_(zetcd_glob_p->zetcd_server);

  /*Carry out the put transaction to put "sample" key into etcd server.*/
  ret = etcd_txn(zetcd_glob_p->txn_put_req);
  if(ret)
  {
    zlog_err("error Unable to push into etcd");
    zetcd_glob_p->conn_retries++;
    /*If failed try another attempt.*/
    zetcd_start_connect_timer("connection failed");
    return -1;
  }
  /*delete opration.*/
  create_del_txn("sample", false, zetcd_glob_p->txn_put_req);
  ret = etcd_txn(zetcd_glob_p->txn_del_req);
  if(ret)
  {
    zlog_err("error Unable to push into etcd");
    zetcd_glob_p->conn_retries++;
    zetcd_start_connect_timer("connection failed");
    return -1;
  }
	zetcd_glob_p->is_connected = true;
	zetcd_connection_up("connection successful");
	return 0;
}

/**
 * zetcd_start_connect_timer
 *
 * Schedule a zetcd_connect_cb task after some assertion.
 *
 * @param[in] t_connect pointer to timer thread object to connect to etcd-server.
 * @param[in] is_connected flag to check the connectivity.
 * */
static void zetcd_start_connect_timer(const char *reason)
{
  zlog_debug("etcd connection thread started as :%s",reason);
  assert(!zetcd_glob_p->t_connect);
  assert(!zetcd_glob_p->is_connected);
  thread_add_timer(zetcd_glob_p->master, zetcd_connect_cb, 0,
      ZETCD_CONNECT_RETRY_IVL,&zetcd_glob_p->t_connect);
}


/**
 *
 * zetcd_init
 *
 * one time initialization of etcd module.
 *
 * @param[in] master master thread of all the tasks.
 * @param[in] zetcd_glob_p pointer to global etcd param structure object.
 * @param[in] dest_q a buffer to store and process updated route entries 
 * pointers for etcd module.
 * @param[in] zetcd_server a string URI to connect to etcd-server via grpc channel.
 * @param[in] obuf a buffer stream to store the protobuf encoded 
 * route entries to be sent to etcd-server.
 * */
static int zetcd_init(struct thread_master *master)
{
  memset(zetcd_glob_p, 0, sizeof(zetcd_glob_t));
  zetcd_glob_p->master = master;
  /*Initializing a queue to store route entries.*/
  TAILQ_INIT(&zetcd_glob_p->dest_q);

  /*Setting etcd default port (2379) and URI "127.0.0.1:2379"*/
  zetcd_glob_p->etcd_port = atoi(ZETCD_DEFAULT_PORT);
  sprintf(zetcd_glob_p->zetcd_server,"%s:%s",ZETCD_DEFAULT_IP,ZETCD_DEFAULT_PORT);

  zetcd_glob_p->is_connected = false;

  /*Creating a buffer of 8192 bytes to store protobuf encoded route entries.*/
  zetcd_glob_p->obuf = stream_new(ZETCD_OBUF_SIZE);

  /*Installing a command to set URI to connect over grpc channel.*/
  install_element(CONFIG_NODE, &etcd_remote_ip_cmd);
  /*Create global GET,PUT and DELETE context*/
  create_txn_context();

  /*Adding a timer task to zebra.*/
  zetcd_start_connect_timer("start connection");
  return 0;
}

/**
 * zebra_etcd_module_init
 *
 * registering to frr_late_init and rib_update hook for etcd initialization 
 * and route update trigger.
 * */
static int zebra_etcd_module_init(void)
{
  /*zetcd_trigger_update called after every route update.*/
  hook_register(rib_update, zetcd_trigger_update);
  /*Initializing etcd parameters after the initialization of FRR.*/
  hook_register(frr_late_init, zetcd_init);
  return 0;
}
/* Add etcd as a zebra module.*/
FRR_MODULE_SETUP(.name = "zebra_etcd", .version = FRR_VERSION,
     .description = "zebra etcd module",
     .init = zebra_etcd_module_init, )
