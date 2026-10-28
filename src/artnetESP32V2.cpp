#include "Arduino.h"
#include "artnetESP32V2.h"
#include "esp_log.h"

extern "C"
{
#include "lwip/opt.h"
#include "lwip/inet.h"
#include "lwip/udp.h"
#include "lwip/igmp.h"
#include "lwip/ip.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/mld6.h"
#include "lwip/prot/ethernet.h"
#include <esp_err.h>
}

#include "lwip/priv/tcpip_priv.h"

#include "artpoll.h"

#define UDP_MUTEX_LOCK()
#define UDP_MUTEX_UNLOCK()

// ─────────────────────────────────────────────────────────────────────────────
// Module state. Lives here, not in the header, so there is exactly one copy.
// ─────────────────────────────────────────────────────────────────────────────
ArtnetStats artnetStats = {0, 0, 0, 0, 0, 0, 0};

static QueueHandle_t            _show_queue[MAX_SUBARTNET];
static QueueHandle_t            _udp_queue       = NULL;
static volatile TaskHandle_t    _udp_task_handle = NULL;

// Set by the sketch to receive ArtPollReply packets for node discovery.
// Invoked from the lwIP receive context — handlers must be short and must not
// block or write to Serial.
static void (*_poll_reply_cb)(const uint8_t *pkt, uint16_t len, uint32_t srcIp) = NULL;

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
// Receive-side helpers. Everything in this section runs on the lwIP tcpip
// task, so it has to be short and must not log, allocate or block.
// ─────────────────────────────────────────────────────────────────────────────

// Hand a packet to the assembly task. Never frees the pbuf: on false the
// caller still owns it and frees it exactly once.
static bool _udp_task_post(const lwip_event_packet_t *e)
{
  if (!_udp_task_handle || !_udp_queue) return false;
  return xQueueSend(_udp_queue, e, 0) == pdPASS;
}

static inline uint32_t _src_ip(const ip_addr_t *addr)
{
  return (addr && IP_IS_V4(addr)) ? ip4_addr_get_u32(ip_2_ip4(addr)) : 0;
}

// One sender per patch. Returns false when a different sender is still
// holding the patch.
static inline bool _source_allowed(subArtnet *s, uint32_t src, uint32_t now)
{
  if (s->lockIp && s->lockIp != src && (now - s->lockMs) < ARTNET_SOURCE_LOCK_MS)
    return false;
  s->lockIp = src;
  s->lockMs = now;
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Art-Net receive callback (port 6454)
// ─────────────────────────────────────────────────────────────────────────────
static void _udp_recv(void *arg, udp_pcb *pcb, pbuf *pb,
                      const ip_addr_t *addr, uint16_t port)
{
  artnetESP32V2 *self = (artnetESP32V2 *)arg;

  while (pb != NULL)
  {
    pbuf *this_pb = pb;
    pb             = pb->next;
    this_pb->next  = NULL;

    const uint8_t *p = (const uint8_t *)this_pb->payload;

    // Anything that is not an Art-Net packet is dropped before it costs a
    // queue slot or a task wake-up. The ID includes its terminating NUL.
    if (this_pb->len < 12 || memcmp(p, "Art-Net", 8) != 0)
    {
      artnetStats.malformed++;
      pbuf_free(this_pb);
      continue;
    }

    uint16_t opcode = p[8] | ((uint16_t)p[9] << 8);

    if (opcode == 0x5000)                      // ArtDMX
    {
      if (this_pb->len < ART_DMX_START + 1)
      {
        artnetStats.malformed++;
        pbuf_free(this_pb);
        continue;
      }

      // Full 15-bit port address: Net (bits 8-14), Sub-Net and Universe.
      int universe = p[14] | ((p[15] & 0x7F) << 8);

      subArtnet *s = self->findSubArtnet(universe);
      if (!s)
      {
        artnetStats.foreign++;
        pbuf_free(this_pb);
        continue;
      }

      if (!_source_allowed(s, _src_ip(addr), sys_now()))
      {
        artnetStats.locked++;
        pbuf_free(this_pb);
        continue;
      }

      // Length is bounded three ways: what the sender declared, what is
      // actually in the packet, and what the patch has room for.
      uint16_t declared = ((uint16_t)p[16] << 8) | p[17];
      uint16_t avail    = this_pb->len - ART_DMX_START;
      uint16_t n        = declared < avail ? declared : avail;
      if (n > (uint16_t)s->nbDataPerUniverse) n = (uint16_t)s->nbDataPerUniverse;
      if (n == 0)
      {
        artnetStats.malformed++;
        pbuf_free(this_pb);
        continue;
      }

      lwip_event_packet_t e;
      e.pb       = this_pb;
      e.sub      = s;
      e.dmx      = p + ART_DMX_START;
      e.len      = n;
      e.universe = universe;
      e.isSacn   = false;

      if (_udp_task_post(&e)) artnetStats.dmx++;
      else { artnetStats.queueFull++; pbuf_free(this_pb); }
    }
    else if (opcode == 0x2000)                 // ArtPoll
    {
      // One broadcast reply serves every device that polled in the window,
      // so a burst of in-phase polls costs one reply, not one per poller.
      static uint32_t lastReply = 0;
      uint32_t now = sys_now();
      artnetStats.polls++;
      if (now - lastReply >= ARTNET_POLLREPLY_MIN_MS)
      {
        lastReply = now;
        poll_reply(pcb);
      }
      pbuf_free(this_pb);
    }
    else if (opcode == 0x2100)                 // ArtPollReply
    {
      // Feed the node table, but never answer: two nodes that each replied
      // to a reply would ping-pong packets at each other forever.
      artnetStats.pollReplies++;
      if (_poll_reply_cb && this_pb->len >= 108)
        _poll_reply_cb(p, this_pb->len, _src_ip(addr));
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
//   4-15  : ACN Packet Identifier
//  18-21  : Root vector (0x00000004 = E1.31 data)
//  40-43  : Framing vector (0x00000002 = DMP)
//  99-100 : Property count (big-endian, includes the start code)
//  113-114: Universe (big-endian, 1-based)
//  125    : DMX start code (0x00 for level data)
//  126+   : DMX payload (up to 512 bytes)
// ─────────────────────────────────────────────────────────────────────────────
static void _sacn_recv(void *arg, udp_pcb *pcb, pbuf *pb,
                       const ip_addr_t *addr, uint16_t port)
{
  artnetESP32V2 *self = (artnetESP32V2 *)arg;

  while (pb != NULL)
  {
    pbuf *this_pb = pb;
    pb             = pb->next;
    this_pb->next  = NULL;

    const uint8_t *p = (const uint8_t *)this_pb->payload;

    if (this_pb->len < SACN_HEADER_SIZE + 1)
    {
      artnetStats.malformed++;
      pbuf_free(this_pb);
      continue;
    }

    uint32_t rootVector = ((uint32_t)p[SACN_ROOT_VECTOR_OFFSET] << 24) |
                          ((uint32_t)p[SACN_ROOT_VECTOR_OFFSET + 1] << 16) |
                          ((uint32_t)p[SACN_ROOT_VECTOR_OFFSET + 2] << 8) |
                          p[SACN_ROOT_VECTOR_OFFSET + 3];
    uint32_t framingVector = ((uint32_t)p[SACN_FRAMING_VECTOR_OFFSET] << 24) |
                             ((uint32_t)p[SACN_FRAMING_VECTOR_OFFSET + 1] << 16) |
                             ((uint32_t)p[SACN_FRAMING_VECTOR_OFFSET + 2] << 8) |
                             p[SACN_FRAMING_VECTOR_OFFSET + 3];

    // Only level data with the null start code drives the strips. Priority
    // packets (start code 0xDD) are ignored.
    if (rootVector != SACN_ROOT_VECTOR_VAL || framingVector != SACN_FRAMING_VECTOR_VAL ||
        p[SACN_START_CODE] != 0x00)
    {
      artnetStats.malformed++;
      pbuf_free(this_pb);
      continue;
    }

    // 1-based on the wire; the library counts universes from 0 like Art-Net.
    uint16_t wireUniverse = ((uint16_t)p[SACN_UNIVERSE_HIGH] << 8) | p[SACN_UNIVERSE_LOW];
    if (wireUniverse == 0)
    {
      artnetStats.malformed++;
      pbuf_free(this_pb);
      continue;
    }
    int universe = (int)wireUniverse - 1;

    subArtnet *s = self->findSubArtnet(universe);
    if (!s)
    {
      artnetStats.foreign++;
      pbuf_free(this_pb);
      continue;
    }

    if (!_source_allowed(s, _src_ip(addr), sys_now()))
    {
      artnetStats.locked++;
      pbuf_free(this_pb);
      continue;
    }

    // Property count includes the start code, so the payload is one less.
    uint16_t props    = ((uint16_t)p[SACN_PROP_COUNT] << 8) | p[SACN_PROP_COUNT + 1];
    uint16_t declared = props ? props - 1 : 0;
    uint16_t avail    = this_pb->len - SACN_HEADER_SIZE;
    uint16_t n        = declared < avail ? declared : avail;
    if (n > (uint16_t)s->nbDataPerUniverse) n = (uint16_t)s->nbDataPerUniverse;
    if (n == 0)
    {
      artnetStats.malformed++;
      pbuf_free(this_pb);
      continue;
    }

    lwip_event_packet_t e;
    e.pb       = this_pb;
    e.sub      = s;
    e.dmx      = p + SACN_HEADER_SIZE;
    e.len      = n;
    e.universe = universe;
    e.isSacn   = true;

    if (_udp_task_post(&e)) artnetStats.dmx++;
    else { artnetStats.queueFull++; pbuf_free(this_pb); }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Frame assembly (runs on the assembly task)
// ─────────────────────────────────────────────────────────────────────────────

// Ship the frame being built and start the next one.
void subArtnet::flushFrame()
{
  uint8_t *d = buffers[currentframenumber];

  // Where this frame ended tells the next one when it is complete, for a
  // sender that patched fewer universes than we did.
  if (highestSeenThisFrame >= 0) observedEnd = highestSeenThisFrame;
  highestSeenThisFrame = -1;
  rxMask     = 0;
  assembling = false;

  currentframenumber = (currentframenumber + 1) % nbOfBuffers;

  if (_using_queues)
  {
    if (xQueueSend(_show_queue[subArtnetNum], &d, 0) != pdTRUE) nb_frames_lost++;
  }
  else
  {
    data = d;
    nb_frames++;
    if (frameCallback) frameCallback((void *)this);
  }
}

// Each universe is written at its own offset, so order does not matter and
// a lost universe only leaves its slice one frame stale: the new frame is
// seeded from the previous one, so every slice always holds the latest
// value that arrived for it.
void subArtnet::handleUniverse(lwip_event_packet_t *e)
{
  int idx = e->universe - startUniverse;
  if (idx < 0 || idx >= nbNeededUniverses) return;
  uint32_t bit = 1UL << idx;

  // The same universe twice means the sender has moved on to the next
  // frame. Ship what we have rather than wait for packets that were lost.
  if (assembling && (rxMask & bit))
  {
    nb_frames_partial++;
    flushFrame();
  }

  if (!assembling)
  {
    assembling = true;
    rxMask     = 0;
    if (nbOfBuffers > 1)
      memcpy(buffers[currentframenumber],
             buffers[(currentframenumber + nbOfBuffers - 1) % nbOfBuffers],
             frameBytes);
  }

  memcpy(buffers[currentframenumber] + (size_t)idx * nbDataPerUniverse, e->dmx, e->len);
  rxMask |= bit;
  if (idx > highestSeenThisFrame) highestSeenThisFrame = idx;

  // Complete: every patched universe is in.
  if (rxMask == fullMask)
  {
    flushFrame();
    return;
  }

  // Adaptive end: the sender patched fewer universes than we did, so the
  // frame is complete when the universe that ended the previous frame
  // arrives and everything below it is already in.
  if (idx == observedEnd)
  {
    uint32_t need = (observedEnd >= 31) ? 0xFFFFFFFFUL : ((1UL << (observedEnd + 1)) - 1);
    if ((rxMask & need) == need) flushFrame();
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
  size_t bytes = frameBytes + 8 + BUFFER_SIZE;
  nbOfBuffers  = 0;

  for (int buffnum = 0; buffnum < NB_MAX_BUFFER; buffnum++)
  {
    buffers[buffnum] = (uint8_t *)calloc(bytes, 1);
    if (buffers[buffnum] == NULL)
    {
      ESP_LOGW("ARTNETESP32", "frame buffer %d: out of heap", buffnum);
      if (leds != NULL && buffnum == 0)
      {
        buffers[0]  = leds;
        nbOfBuffers = 1;
      }
      break;
    }
    nbOfBuffers = buffnum + 1;
  }
  ESP_LOGI("ARTNETESP32", "frame buffers: %d x %u bytes", nbOfBuffers, (unsigned)bytes);
}

void subArtnet::_initialize(int star_universe, uint32_t nb_data,
                            uint32_t nb_data_per_universe, uint8_t *leds)
{
  nb_frames         = 0;
  nb_frame_double   = 0;
  nb_frames_lost    = 0;
  nb_frames_partial = 0;
  previous_lost     = 0;
  _nb_data          = nb_data;
  nbDataPerUniverse = nb_data_per_universe;
  startUniverse     = star_universe;
  nbNeededUniverses = nb_data / nbDataPerUniverse;
  if (nbNeededUniverses * nbDataPerUniverse < nb_data) nbNeededUniverses++;
  if (nbNeededUniverses > MAX_UNIVERSES_PER_PATCH)
  {
    ESP_LOGW("ARTNETESP32", "patch of %d universes clamped to %d",
             nbNeededUniverses, MAX_UNIVERSES_PER_PATCH);
    nbNeededUniverses = MAX_UNIVERSES_PER_PATCH;
  }
  len         = nb_data;
  endUniverse = startUniverse + nbNeededUniverses;
  frameBytes  = (size_t)nbDataPerUniverse * nbNeededUniverses;

  rxMask               = 0;
  fullMask             = (nbNeededUniverses >= 32) ? 0xFFFFFFFFUL
                                                   : ((1UL << nbNeededUniverses) - 1);
  assembling           = false;
  observedEnd          = nbNeededUniverses - 1;
  highestSeenThisFrame = -1;
  lockIp               = 0;
  lockMs               = 0;
  data                 = NULL;

  ESP_LOGI("ARTNETESP32",
           "Initialize subArtnet Start Universe: %d  end Universe: %d, universes %d",
           startUniverse, endUniverse - 1, nbNeededUniverses);
  createBuffers(leds);
  currentframenumber = 0;
}

subArtnet::~subArtnet()
{
  for (int i = 0; i < nbOfBuffers; i++)
    if (buffers[i] != NULL) free(buffers[i]);
}

uint8_t *subArtnet::getData()
{
  return data;
}

// ─────────────────────────────────────────────────────────────────────────────
// Assembly task: takes packets off _udp_queue and writes them into frames
// ─────────────────────────────────────────────────────────────────────────────
static void _udp_task_subrarnet(void *pvParameters)
{
  lwip_event_packet_t e;
  artnetESP32V2 *artnet = (artnetESP32V2 *)pvParameters;

  for (int i = 0; i < artnet->numSubArtnet; i++)
  {
    subArtnet *s = artnet->subArtnets[i];
    ESP_LOGI("ARTNETESP32", "subArtnet nr:%d start universe:%d Nb Universes: %d",
             s->subArtnetNum, s->startUniverse, s->nbNeededUniverses);
  }

  for (;;)
  {
    if (xQueueReceive(_udp_queue, &e, portMAX_DELAY) == pdTRUE)
    {
      if (!e.pb) continue;
      if (e.sub) e.sub->handleUniverse(&e);
      pbuf_free(e.pb);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-patch LED task: newest frame wins
// ─────────────────────────────────────────────────────────────────────────────
static void _udp_task_subrarnet_handle(void *pvParameters)
{
  subArtnet *subartnet = (subArtnet *)pvParameters;
  uint8_t   *data      = NULL;
  QueueHandle_t q      = _show_queue[subartnet->subArtnetNum];

  for (;;)
  {
    if (xQueueReceive(q, &data, portMAX_DELAY) == pdTRUE)
    {
      // If the strips fell behind, skip straight to the newest frame instead
      // of playing a backlog. Frames are seeded, so nothing is lost by it.
      uint8_t *newer;
      while (xQueueReceive(q, &newer, 0) == pdTRUE)
      {
        data = newer;
        subartnet->nb_frame_double++;
      }

      subartnet->data = data;
      subartnet->nb_frames++;
      if (subartnet->frameCallback) subartnet->frameCallback((void *)subartnet);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Queue / task startup (called from listen())
// ─────────────────────────────────────────────────────────────────────────────
static bool _udp_task_start(artnetESP32V2 *p)
{
  if (!_udp_queue)
  {
    _udp_queue = xQueueCreate(128, sizeof(lwip_event_packet_t));
    if (!_udp_queue) return false;
  }
  for (int i = 0; i < p->numSubArtnet; i++)
  {
    if (!_show_queue[i])
    {
      _show_queue[i] = xQueueCreate(NB_MAX_BUFFER, sizeof(uint8_t *));
      if (!_show_queue[i])
      {
        ESP_LOGE("ARTNETESP32", "show queue %d not created", i);
        return false;
      }
    }
  }
  if (!_udp_task_handle)
  {
    xTaskCreateUniversal(_udp_task_subrarnet, "_udp_task_subrarnet", 4096, p,
                         CONFIG_ARDUINO_UDP_TASK_PRIORITY,
                         (TaskHandle_t *)&_udp_task_handle, SUBARTNET_CORE);
    if (!_udp_task_handle)
    {
      ESP_LOGE("ARTNETESP32", "assembly task not created");
      return false;
    }
  }
  return true;
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

bool artnetESP32V2::_init()
{
  if (_pcb) return true;
  _pcb = udp_new();
  if (!_pcb) return false;
  udp_recv(_pcb, &_udp_recv, (void *)this);
  return true;
}

bool artnetESP32V2::_initSACN()
{
  if (_sacn_pcb) return true;

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

// sACN multicast address for universe N is 239.255.(N>>8).(N&0xFF), with N
// the 1-based sACN universe (= library universe + 1).
void artnetESP32V2::joinSACNMulticast(int startUniverse, int numUniverses)
{
  if (protocolMode == PROTOCOL_ARTNET) return;

  for (int i = 0; i < numUniverses; i++)
  {
    int sacnUniverse = startUniverse + i + 1;
    ip4_addr_t mcast;
    IP4_ADDR(&mcast, 239, 255, (sacnUniverse >> 8) & 0xFF, sacnUniverse & 0xFF);

    if (igmp_joingroup(IP4_ADDR_ANY4, &mcast) != ERR_OK)
      ESP_LOGW("ARTNETESP32", "igmp_joingroup failed for sACN universe %d", sacnUniverse);
    else
      ESP_LOGI("ARTNETESP32", "Joined sACN multicast for universe %d", sacnUniverse);
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

  char mess[32];
  for (int i = 0; i < numSubArtnet; i++)
  {
    if (subArtnets[i]->_using_queues)
    {
      snprintf(mess, sizeof(mess), "handle_subartnet_%d", i);
      subArtnets[i]->subArtnet_sem = xSemaphoreCreateBinary();
      xTaskCreateUniversal(_udp_task_subrarnet_handle, mess, 4096,
                           subArtnets[i], 3, NULL, CALLBACK_CORE);
    }
  }

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

  if (protocolMode != PROTOCOL_ARTNET)
  {
    if (!_initSACN())
      ESP_LOGW("ARTNETESP32", "sACN init failed — continuing with ArtNet only");
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

// ─────────────────────────────────────────────────────────────────────────────
// Node discovery
// ─────────────────────────────────────────────────────────────────────────────
void artnetESP32V2::setPollReplyCallback(
    void (*fptr)(const uint8_t *pkt, uint16_t len, uint32_t srcIp))
{
  _poll_reply_cb = fptr;
}

// Build and broadcast the ArtPoll inside the tcpip thread. Everything lwIP
// touches has to happen there — sendArtPoll() is called from loop().
static err_t _udp_sendpoll_api(struct tcpip_api_call_data *api_call_msg)
{
  udp_api_call_t *msg = (udp_api_call_t *)api_call_msg;

  // ArtPoll: ID[8], OpCode 0x2000 (little-endian on the wire), ProtVer 14,
  // TalkToMe 0x02 (reply on change), DiagPriority 0x10 (low).
  static const uint8_t poll[14] = {
    'A', 'r', 't', '-', 'N', 'e', 't', 0x00,
    0x00, 0x20, 0x00, 0x0E, 0x02, 0x10
  };

  pbuf *pb = pbuf_alloc(PBUF_TRANSPORT, sizeof(poll), PBUF_RAM);
  if (!pb)
  {
    msg->err = ERR_MEM;
    return msg->err;
  }
  memcpy(pb->payload, poll, sizeof(poll));

  ip_set_option(msg->pcb, SOF_BROADCAST);
  msg->err = udp_sendto(msg->pcb, pb, IP_ADDR_BROADCAST, DEFAULT_PORT);
  pbuf_free(pb);
  return msg->err;
}

bool artnetESP32V2::sendArtPoll()
{
  if (!_pcb) return false;

  udp_api_call_t msg;
  msg.pcb = _pcb;
  msg.err = ERR_OK;
  tcpip_api_call(_udp_sendpoll_api, (struct tcpip_api_call_data *)&msg);
  return msg.err == ERR_OK;
}
