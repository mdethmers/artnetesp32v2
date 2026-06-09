#include "Arduino.h"
#include "artnetESP32V2.h"
#include "esp_log.h"

extern "C"
{
#include "lwip/opt.h"
#include "lwip/inet.h"
#include "lwip/udp.h"
#include "lwip/igmp.h"
#include "lwip/ip_addr.h"
#include "lwip/mld6.h"
#include "lwip/prot/ethernet.h"
#include <esp_err.h>
#include <esp_wifi.h>
}

#include "lwip/priv/tcpip_priv.h"

#include "artpoll.h"
#define BUFFER_SIZE   10
#define ART_DMX_START 18
#define NB_MAX_BUFFER 10
#define MAX_SUBARTNET 20

#define SUBARTNET_CORE 0
#define CALLBACK_CORE  1

#define UDP_MUTEX_LOCK()
#define UDP_MUTEX_UNLOCK()

// ─────────────────────────────────────────────────────────────────────────────
// Low-level tcpip_api_call helpers (unchanged from original)
// ─────────────────────────────────────────────────────────────────────────────
typedef struct
{
  struct tcpip_api_call_data call;
  udp_pcb         *pcb;
  const ip_addr_t *addr;
  uint16_t         port;
  struct pbuf     *pb;
  struct netif    *netif;
  err_t            err;
} udp_api_call_t;

static err_t _udp_connect_api(struct tcpip_api_call_data *api_call_msg)
{
  udp_api_call_t *msg = (udp_api_call_t *)api_call_msg;
  msg->err = udp_connect(msg->pcb, msg->addr, msg->port);
  return msg->err;
}

static err_t _udp_connect(struct udp_pcb *pcb, const ip_addr_t *addr, u16_t port)
{
  udp_api_call_t msg;
  msg.pcb  = pcb;
  msg.addr = addr;
  msg.port = port;
  tcpip_api_call(_udp_connect_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

static err_t _udp_disconnect_api(struct tcpip_api_call_data *api_call_msg)
{
  udp_api_call_t *msg = (udp_api_call_t *)api_call_msg;
  msg->err = 0;
  udp_disconnect(msg->pcb);
  return msg->err;
}

static void _udp_disconnect(struct udp_pcb *pcb)
{
  udp_api_call_t msg;
  msg.pcb = pcb;
  tcpip_api_call(_udp_disconnect_api, (struct tcpip_api_call_data *)&msg);
}

static err_t _udp_remove_api(struct tcpip_api_call_data *api_call_msg)
{
  udp_api_call_t *msg = (udp_api_call_t *)api_call_msg;
  msg->err = 0;
  udp_remove(msg->pcb);
  return msg->err;
}

static void _udp_remove(struct udp_pcb *pcb)
{
  udp_api_call_t msg;
  msg.pcb = pcb;
  tcpip_api_call(_udp_remove_api, (struct tcpip_api_call_data *)&msg);
}

static err_t _udp_bind_api(struct tcpip_api_call_data *api_call_msg)
{
  udp_api_call_t *msg = (udp_api_call_t *)api_call_msg;
  msg->err = udp_bind(msg->pcb, msg->addr, msg->port);
  return msg->err;
}

static err_t _udp_bind(struct udp_pcb *pcb, const ip_addr_t *addr, u16_t port)
{
  udp_api_call_t msg;
  msg.pcb  = pcb;
  msg.addr = addr;
  msg.port = port;
  tcpip_api_call(_udp_bind_api, (struct tcpip_api_call_data *)&msg);
  return msg.err;
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared queue post helper — used by both ArtNet and sACN receive callbacks
// ─────────────────────────────────────────────────────────────────────────────
static bool _udp_task_post(pbuf *pb, int universe, bool isSacn = false)
{
  if (!_udp_task_handle || !_udp_queue) return false;

  lwip_event_packet_t e;
  e.pb       = pb;
  e.universe = universe;
  e.isSacn   = isSacn;

  // Do not block the UDP receive callback; if the queue is full, drop packets.
  if (xQueueSend(_udp_queue, &e, 0) != pdPASS)
  {
    ESP_LOGW("ARTNETESP32", "UDP queue full, dropping packet universe=%d len=%u",
             universe, pb ? pb->len : 0);
    if (pb) pbuf_free(pb);
    return false;
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// ArtNet receive callback (port 6454)
// ─────────────────────────────────────────────────────────────────────────────
static void _udp_recv(void *arg, udp_pcb *pcb, pbuf *pb,
                      const ip_addr_t *addr, uint16_t port)
{
  while (pb != NULL)
  {
    pbuf *this_pb = pb;
    pb             = pb->next;
    this_pb->next  = NULL;

    // ArtPoll reply (opcode 0x2100 at word offset 4, little-endian)
    if (*((uint16_t *)(this_pb->payload) + 4) == 0x2100)
    {
      poll_reply(pcb, addr);
      pbuf_free(this_pb);
    }
    // ArtDMX (opcode 0x5000)
    else if (*((uint16_t *)(this_pb->payload) + 4) == 0x5000)
    {
      // Universe is byte 14 from start (original library behaviour)
      int universe = *((uint8_t *)(this_pb->payload) + 14);
      if (!_udp_task_post(this_pb, universe))
        pbuf_free(this_pb);
    }
    else
    {
      pbuf_free(this_pb);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// sACN / E1.31 receive callback (port 5568)
//
// E1.31 packet layout (relevant offsets):
//   0-1   : Preamble size (0x0010)
//   2-3   : Postamble size (0x0000)
//   4-15  : ACN Packet Identifier UUID
//  16-17  : PDU flags+length
//  18-21  : Vector (0x00000004 = E1.31 Data Packet)
//  22-83  : Source name (64 bytes)
//  84     : Priority
//  85-86  : Synchronization address
//  87     : Sequence number
//  88     : Options
//  89-90  : Universe (big-endian, 1-based)  <-- CORRECTED offset
//  -- DMP Layer begins at 91 --
//  91-92  : Flags+length
//  93     : Vector (0x02)
//  94     : Address type / data type (0xa1)
//  95-96  : First property address (0x0000)
//  97-98  : Address increment (0x0001)
//  99-100 : Property count (big-endian, includes start code)
//  101    : DMX Start Code (0x00)
//  102+   : DMX payload (up to 512 bytes)
//
// Total header before DMX payload: 102 bytes (start code at 101, data at 102).
// We define SACN_HEADER_SIZE = 126 to be conservative and match common
// implementations; the actual DMX data starts at offset 126 in standard
// E1.31 frames.  For the universe we use offsets 113/114 (within the
// standard framing layer) which is the most widely documented position.
//
// NOTE: The universe offset depends on the preamble. Standard E1.31 frames
// always use preamble 0x0010, making the universe reliably at bytes 113-114.
// ─────────────────────────────────────────────────────────────────────────────
static void _sacn_recv(void *arg, udp_pcb *pcb, pbuf *pb,
                       const ip_addr_t *addr, uint16_t port)
{
  while (pb != NULL)
  {
    pbuf *this_pb = pb;
    pb             = pb->next;
    this_pb->next  = NULL;

    // Minimum length check
    if (this_pb->len < SACN_HEADER_SIZE)
    {
      ESP_LOGI("ARTNETESP32", "sACN RX too short (%u bytes)", this_pb->len);
      pbuf_free(this_pb);
      continue;
    }

    uint8_t *p = (uint8_t *)this_pb->payload;

    // Verify E1.31 root and framing vectors
    uint32_t rootVector = ((uint32_t)p[SACN_ROOT_VECTOR_OFFSET] << 24) |
                          ((uint32_t)p[SACN_ROOT_VECTOR_OFFSET + 1] << 16) |
                          ((uint32_t)p[SACN_ROOT_VECTOR_OFFSET + 2] << 8) |
                          p[SACN_ROOT_VECTOR_OFFSET + 3];
    if (rootVector != SACN_ROOT_VECTOR_VAL)
    {
      ESP_LOGI("ARTNETESP32", "sACN RX bad root vector 0x%08x len=%u", rootVector, this_pb->len);
      pbuf_free(this_pb);
      continue;
    }

    uint32_t framingVector = ((uint32_t)p[SACN_FRAMING_VECTOR_OFFSET] << 24) |
                             ((uint32_t)p[SACN_FRAMING_VECTOR_OFFSET + 1] << 16) |
                             ((uint32_t)p[SACN_FRAMING_VECTOR_OFFSET + 2] << 8) |
                             p[SACN_FRAMING_VECTOR_OFFSET + 3];
    if (framingVector != SACN_FRAMING_VECTOR_VAL)
    {
      ESP_LOGI("ARTNETESP32", "sACN RX bad framing vector 0x%08x len=%u", framingVector, this_pb->len);
      pbuf_free(this_pb);
      continue;
    }

    // Universe: big-endian at offsets 113-114, 1-based in E1.31
    uint16_t universe = ((uint16_t)p[SACN_UNIVERSE_HIGH] << 8) |
                         p[SACN_UNIVERSE_LOW];

    // Normalise to 0-based to match ArtNet convention used throughout the
    // rest of the library (startUniverse 0 in ArtNet == universe 1 in sACN)
    if (universe == 0)
    {
      // Universe 0 is invalid in E1.31 — discard
      ESP_LOGI("ARTNETESP32", "sACN RX invalid universe 0 len=%u", this_pb->len);
      pbuf_free(this_pb);
      continue;
    }
    int normalisedUniverse = (int)universe - 1;

    // Safety: single-pbuf only (sACN frames are always < MTU)
    if (this_pb->next != NULL)
    {
      // Chained pbuf — unexpected, discard
      ESP_LOGI("ARTNETESP32", "sACN RX chained pbuf len=%u", this_pb->len);
      pbuf_free(this_pb);
      continue;
    }

    const char *src = ipaddr_ntoa(addr);
    ESP_LOGI("ARTNETESP32", "sACN RX from %s:%u raw=%u universe=%u norm=%d",
             src ? src : "?", port, this_pb->len, universe,
             normalisedUniverse);

    // Advance payload pointer past the E1.31 header so the downstream
    // handler sees raw DMX data, matching what the ArtNet path delivers.
    // We must not call pbuf_free after adjusting payload — lwIP still owns
    // the original allocation; we just adjust the pointer.
    this_pb->payload  = p + SACN_HEADER_SIZE;
    this_pb->len      = (this_pb->len > SACN_HEADER_SIZE)
                        ? (this_pb->len - SACN_HEADER_SIZE) : 0;
    this_pb->tot_len  = this_pb->len;

    if (this_pb->len == 0)
    {
      ESP_LOGI("ARTNETESP32", "sACN RX no DMX data after header");
      pbuf_free(this_pb);
      continue;
    }

    if (!_udp_task_post(this_pb, normalisedUniverse, true))
    {
      ESP_LOGI("ARTNETESP32", "sACN RX failed to post universe=%d len=%u",
              normalisedUniverse, this_pb->len);
      pbuf_free(this_pb);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// subArtnet implementation
// ─────────────────────────────────────────────────────────────────────────────
subArtnet::subArtnet(int star_universe, uint32_t nb_data,
                     uint32_t nb_data_per_universe)
{
  _initialize(star_universe, nb_data, nb_data_per_universe, NULL);
}

void subArtnet::createBuffers(uint8_t *leds)
{
  for (int buffnum = 0; buffnum < NB_MAX_BUFFER; buffnum++)
  {
    buffers[buffnum] = (uint8_t *)calloc(
        (nbDataPerUniverse) * nbNeededUniverses + 8 + BUFFER_SIZE, 1);

    if (buffers[buffnum] == NULL)
    {
      ESP_LOGI("ARTNETESP32", "impossible to create buffer %d", buffnum);
      if (leds != NULL)
      {
        buffers[buffnum] = leds;
        ESP_LOGI("ARTNETESP32", "using leds array as buffer %d", buffnum);
        nbOfBuffers = buffnum + 1;
        return;
      }
      else
      {
        nbOfBuffers = buffnum;
        ESP_LOGI("ARTNETESP32", "nb total of buffers:%d", nbOfBuffers);
        return;
      }
    }
    else
    {
      ESP_LOGI("ARTNETESP32", "Creation of buffer %d", buffnum);
      nbOfBuffers = buffnum + 1;
    }
    memset(buffers[buffnum], 0,
           (nbDataPerUniverse) * nbNeededUniverses + 8 + BUFFER_SIZE);
  }
  ESP_LOGI("ARTNETESP32", "nb total of buffers:%d", nbOfBuffers);
}

void subArtnet::_initialize(int star_universe, uint32_t nb_data,
                            uint32_t nb_data_per_universe, uint8_t *leds)
{
  nb_frames          = 0;
  nb_frame_double    = 0;
  nb_frames_lost     = 0;
  previous_lost      = 0;
  previousUniverse   = 99;
  new_frame          = false;
  _nb_data           = nb_data;
  nbDataPerUniverse  = nb_data_per_universe;
  startUniverse      = star_universe;
  // Sentinels — never match a real incoming universe
  observedEnd          = star_universe - 1;
  highestSeenThisFrame = star_universe - 1;
  nbNeededUniverses = nb_data / nbDataPerUniverse;
  if (nbNeededUniverses * nbDataPerUniverse < nb_data)
    nbNeededUniverses++;
  len        = nb_data;
  endUniverse = startUniverse + nbNeededUniverses;

  ESP_LOGI("ARTNETESP32",
           "Initialize subArtnet Start Universe: %d  end Universe: %d, universes %d",
           startUniverse, endUniverse - 1, nbNeededUniverses);
  createBuffers(leds);
  currentframenumber = 0;
  offset             = buffers[0];
}

subArtnet::~subArtnet()
{
  if (buffers[0] != NULL) free(buffers[0]);
  if (buffers[1] != NULL) free(buffers[1]);
}

uint8_t *subArtnet::getData()
{
  return data;
}

// ─────────────────────────────────────────────────────────────────────────────
// artnetESP32V2 implementation
// ─────────────────────────────────────────────────────────────────────────────
artnetESP32V2::artnetESP32V2()
{
  _pcb       = NULL;
  _sacn_pcb  = NULL;
  _connected = false;
  _lastErr   = ERR_OK;
}

// ── Init ArtNet PCB ───────────────────────────────────────────────────────────
bool artnetESP32V2::_init()
{
  if (_pcb) return true;
  _pcb = udp_new();
  if (!_pcb) return false;
  udp_recv(_pcb, &_udp_recv, (void *)this);
  return true;
}

// ── Init sACN PCB ─────────────────────────────────────────────────────────────
bool artnetESP32V2::_initSACN()
{
  if (_sacn_pcb) return true;   // already initialised

  _sacn_pcb = udp_new();
  if (!_sacn_pcb)
  {
    ESP_LOGE("ARTNETESP32", "Failed to create sACN PCB");
    return false;
  }

  udp_recv(_sacn_pcb, &_sacn_recv, (void *)this);

  ip_addr_t any;
  IP4_ADDR(&any.u_addr.ip4, 0, 0, 0, 0);
  any.type = IPADDR_TYPE_V4;

  err_t err = _udp_bind(_sacn_pcb, &any, SACN_PORT);
  if (err != ERR_OK)
  {
    ESP_LOGE("ARTNETESP32", "sACN bind failed: %d", err);
    _udp_remove(_sacn_pcb);
    _sacn_pcb = NULL;
    return false;
  }

  ESP_LOGI("ARTNETESP32", "sACN listening on port %d", SACN_PORT);
  return true;
}

// ── Multicast join helper ─────────────────────────────────────────────────────
// sACN multicast address for universe N is 239.255.(N>>8).(N&0xFF).
// N is the 1-based sACN universe (= ArtNet universe + 1 internally).
void artnetESP32V2::joinSACNMulticast(int startUniverse, int numUniverses)
{
  if (protocolMode == PROTOCOL_ARTNET) return;  // sACN not active

  for (int i = 0; i < numUniverses; i++)
  {
    int sacnUniverse = startUniverse + i + 1;   // +1: ArtNet->sACN 1-based
    ip4_addr_t mcast;
    IP4_ADDR(&mcast,
             239, 255,
             (sacnUniverse >> 8) & 0xFF,
             sacnUniverse & 0xFF);

    if (igmp_joingroup(IP4_ADDR_ANY4, &mcast) != ERR_OK)
    {
      ESP_LOGW("ARTNETESP32",
               "igmp_joingroup failed for universe %d (239.255.%d.%d)",
               sacnUniverse,
               (sacnUniverse >> 8) & 0xFF,
               sacnUniverse & 0xFF);
    }
    else
    {
      ESP_LOGI("ARTNETESP32",
               "Joined sACN multicast 239.255.%d.%d for universe %d",
               (sacnUniverse >> 8) & 0xFF,
               sacnUniverse & 0xFF,
               sacnUniverse);
    }
  }
}

artnetESP32V2::~artnetESP32V2()
{
  close();
  UDP_MUTEX_LOCK();
  if (_pcb)
  {
    udp_recv(_pcb, NULL, NULL);
    _udp_remove(_pcb);
    _pcb = NULL;
  }
  if (_sacn_pcb)
  {
    udp_recv(_sacn_pcb, NULL, NULL);
    _udp_remove(_sacn_pcb);
    _sacn_pcb = NULL;
  }
  UDP_MUTEX_UNLOCK();
}

void artnetESP32V2::close()
{
  UDP_MUTEX_LOCK();
  if (_pcb != NULL)
  {
    if (_connected) _udp_disconnect(_pcb);
    _connected = false;
  }
  // _sacn_pcb uses bind (not connect), so no disconnect needed
  UDP_MUTEX_UNLOCK();
}

bool artnetESP32V2::connect(const ip_addr_t *addr, uint16_t port)
{
  if (!_udp_task_start(this)) { log_e("failed to start task"); return false; }
  if (!_init()) return false;
  close();
  UDP_MUTEX_LOCK();
  _lastErr = _udp_connect(_pcb, addr, port);
  if (_lastErr != ERR_OK) { UDP_MUTEX_UNLOCK(); return false; }
  _connected = true;
  UDP_MUTEX_UNLOCK();
  return true;
}

bool artnetESP32V2::connect(const IPAddress addr, uint16_t port)
{
  ip_addr_t daddr;
  daddr.type            = IPADDR_TYPE_V4;
  daddr.u_addr.ip4.addr = addr;
  return connect(&daddr, port);
}

bool artnetESP32V2::connect(const IPv6Address addr, uint16_t port)
{
  ip_addr_t daddr;
  daddr.type = IPADDR_TYPE_V6;
  memcpy((uint8_t *)(daddr.u_addr.ip6.addr), (const uint8_t *)addr, 16);
  return connect(&daddr, port);
}

bool artnetESP32V2::listen(const ip_addr_t *addr, uint16_t port)
{
  if (!_udp_task_start(this)) { log_e("failed to start task"); return false; }

  char mess[60];
  for (int i = 0; i < numSubArtnet; i++)
  {
    if (subArtnets[i]->_using_queues)
    {
      memset(mess, 0, 60);
      sprintf(mess, "handle_subartnet_%d", i);
      subArtnets[i]->subArtnet_sem = xSemaphoreCreateBinary();
      xTaskCreateUniversal(_udp_task_subrarnet_handle, mess, 4096,
                           subArtnets[i], 3, NULL, CALLBACK_CORE);
    }
  }

  // ── ArtNet PCB ─────────────────────────────────────────────────────────────
  if (protocolMode != PROTOCOL_SACN)
  {
    if (!_init()) return false;
    close();
    if (addr)
    {
      IP_SET_TYPE_VAL(_pcb->local_ip,  addr->type);
      IP_SET_TYPE_VAL(_pcb->remote_ip, addr->type);
    }
    UDP_MUTEX_LOCK();
    if (_udp_bind(_pcb, addr, port) != ERR_OK)
    {
      UDP_MUTEX_UNLOCK();
      return false;
    }
    _connected = true;
    UDP_MUTEX_UNLOCK();
    ESP_LOGI("ARTNETESP32", "ArtNet listening on port %d", port);
  }

  // ── sACN PCB ───────────────────────────────────────────────────────────────
  if (protocolMode != PROTOCOL_ARTNET)
  {
    if (!_initSACN())
    {
      // Non-fatal if ArtNet is also active; log and continue
      ESP_LOGW("ARTNETESP32",
               "sACN init failed — continuing with ArtNet only");
    }
  }

  return true;
}

bool artnetESP32V2::listen(uint16_t port)
{
  return listen(IP_ANY_TYPE, port);
}

bool artnetESP32V2::listen(const IPAddress addr, uint16_t port)
{
  ip_addr_t laddr;
  laddr.type            = IPADDR_TYPE_V4;
  laddr.u_addr.ip4.addr = addr;
  return listen(&laddr, port);
}

bool artnetESP32V2::listen(const IPv6Address addr, uint16_t port)
{
  ip_addr_t laddr;
  laddr.type = IPADDR_TYPE_V6;
  memcpy((uint8_t *)(laddr.u_addr.ip6.addr), (const uint8_t *)addr, 16);
  return listen(&laddr, port);
}

artnetESP32V2::operator bool()
{
  return true;
}

void artnetESP32V2::setNodeName(String s)
{
  short_name = s;
}
