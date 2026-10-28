#ifndef ARTNETESP32_H
#define ARTNETESP32_H
#include "Arduino.h"
#include "IPAddress.h"
#include "IPv6Address.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
extern "C"
{
#include "freertos/queue.h"
#include "freertos/semphr.h"
}
#include "lwip/ip_addr.h"

struct udp_pcb;
struct pbuf;
class  subArtnet;

// One received DMX universe, handed from the lwIP receive callback to the
// assembly task. Whoever holds the event owns the pbuf; the task frees it
// after copying. dmx points into the pbuf, past the protocol header.
typedef struct
{
  pbuf          *pb;
  subArtnet     *sub;        // patch this universe belongs to (resolved on receive)
  const uint8_t *dmx;        // first DMX byte
  uint16_t       len;        // DMX bytes available, already clamped to the patch
  int            universe;   // 15-bit Art-Net port address / 0-based sACN universe
  bool           isSacn;
} lwip_event_packet_t;

#define ART_DMX_START    18
#define BUFFER_SIZE      512
#define MAX_SUBARTNET    20

// Frame buffers per patch. Each one holds a whole frame (universes x 510
// bytes). With frames seeded from the previous one and the LED task always
// taking the newest queued frame, four is enough: one being clocked out to
// the strips, one or two queued, one being filled.
#ifndef NB_MAX_BUFFER
#define NB_MAX_BUFFER    4
#endif

// Universes one patch may span. The assembly bitmask is 32 bits wide.
#define MAX_UNIVERSES_PER_PATCH 32

// A second sender on the same universes is ignored for this long after the
// last packet from the first one. Keeps a stray controller from interleaving
// its frames with the real one; switching consoles costs at most this gap.
#ifndef ARTNET_SOURCE_LOCK_MS
#define ARTNET_SOURCE_LOCK_MS 1000
#endif

// Minimum spacing between ArtPollReply broadcasts. One broadcast reply serves
// every device that polled in that window. Controllers poll every 2.5-3 s and
// tolerate a missed reply, so 2 s still answers every poll a console sends
// while a dozen nodes polling in phase cost one reply instead of twelve.
#ifndef ARTNET_POLLREPLY_MIN_MS
#define ARTNET_POLLREPLY_MIN_MS 2000
#endif

// ── sACN / E1.31 constants ────────────────────────────────────────────────────
#define SACN_PORT           5568
#define SACN_HEADER_SIZE    126   // bytes before DMX payload in E1.31
#define SACN_START_CODE     125   // DMX start code sits just before the payload
#define SACN_PROP_COUNT     99    // big-endian property count (includes start code)
#define SACN_UNIVERSE_HIGH  113   // big-endian universe MSB offset
#define SACN_UNIVERSE_LOW   114   // big-endian universe LSB offset
#define SACN_ROOT_VECTOR_OFFSET    18
#define SACN_ROOT_VECTOR_VAL       0x00000004
#define SACN_FRAMING_VECTOR_OFFSET 40
#define SACN_FRAMING_VECTOR_VAL    0x00000002

#ifndef  _USING_QUEUES
#define _USING_QUEUES 1
#endif
#ifndef SUBARTNET_CORE
#define SUBARTNET_CORE 0
#endif
#ifndef CALLBACK_CORE
#define CALLBACK_CORE 1
#endif

// ── Protocol mode ─────────────────────────────────────────────────────────────
#define PROTOCOL_ARTNET 0
#define PROTOCOL_SACN   1
#define PROTOCOL_BOTH   2

// ── Receive-side counters ─────────────────────────────────────────────────────
// Bumped from the lwIP receive context instead of logging there. Read them
// from the sketch (e.g. print every few seconds) to see what the network is
// doing to the node.
struct ArtnetStats
{
  volatile uint32_t dmx;         // ArtDMX / sACN data packets accepted
  volatile uint32_t foreign;     // data for universes this node does not patch
  volatile uint32_t locked;      // data from a second sender, dropped by the lock
  volatile uint32_t malformed;   // wrong ID, too short, bad start code
  volatile uint32_t queueFull;   // accepted but dropped: assembly task fell behind
  volatile uint32_t polls;       // ArtPoll seen
  volatile uint32_t pollReplies; // ArtPollReply seen
};
extern ArtnetStats artnetStats;

// ─────────────────────────────────────────────────────────────────────────────
class subArtnet
{
public:
  int startUniverse, endUniverse, nbDataPerUniverse, nbNeededUniverses;

  // Frame counters, kept as plain ints for sketches that print them.
  int nb_frames;          // frames handed to the callback
  int nb_frames_lost;     // frames dropped because the show queue was full
  int nb_frame_double;    // frames skipped because a newer one was already queued
  int nb_frames_partial;  // frames shipped by a repeat before every universe arrived
  int previous_lost;

  uint8_t *buffers[NB_MAX_BUFFER];
  uint8_t  currentframenumber;
  uint8_t  nbOfBuffers = 2;
  uint8_t *data;
  size_t   len;
  uint32_t _nb_data;
  size_t   frameBytes;

  // Frame assembly. Each universe lands at its own offset; a frame ships when
  // every patched universe is in, when the universe that ended the previous
  // frame arrives (sender patched fewer than we did), or when a universe
  // repeats (the sender has started the next frame).
  uint32_t rxMask, fullMask;
  bool     assembling;
  int      observedEnd;           // index of the last universe of the previous frame
  int      highestSeenThisFrame;

  // Source lock, see ARTNET_SOURCE_LOCK_MS. Touched from the lwIP context only.
  uint32_t lockIp, lockMs;

  void   (*frameCallback)(void *params);
  int      subArtnetNum;
  uint8_t  _callback_core = CALLBACK_CORE;
  bool     _using_queues;
  bool     subartnetglag;
  long     time1, time2;

  volatile SemaphoreHandle_t subArtnet_sem = NULL;

  subArtnet(int star_universe, uint32_t nb_data, uint32_t nb_data_per_universe);
  void createBuffers(uint8_t *leds);
  void _initialize(int star_universe, uint32_t nb_data, uint32_t nb_data_per_universe, uint8_t *leds);
  ~subArtnet();

  void handleUniverse(lwip_event_packet_t *e);   // runs on the assembly task
  void flushFrame();

  uint8_t *getData();
  void setFrameCallback(void (*fptr)(void *params)) { frameCallback = fptr; }
};

// ─────────────────────────────────────────────────────────────────────────────
class artnetESP32V2
{
protected:
  udp_pcb  *_pcb;        // Art-Net UDP PCB (port 6454)
  udp_pcb  *_sacn_pcb;   // sACN UDP PCB   (port 5568)
  bool      _connected;
  esp_err_t _lastErr;

  bool _init();
  bool _initSACN();

public:
  int      num_universes, numSubArtnet = 0;
  uint8_t *artnetleds1, *buffer2;
  uint8_t *currentframe;
  uint8_t  _udp_task_core = SUBARTNET_CORE;
  uint32_t pixels_per_universe, nbPixels, nbPixelsPerUniverse,
           nbNeededUniverses, startuniverse, enduniverse, nbframes, nbframeslost;

  // PROTOCOL_ARTNET (0), PROTOCOL_SACN (1), PROTOCOL_BOTH (2)
  int protocolMode = PROTOCOL_BOTH;

  artnetESP32V2();
  ~artnetESP32V2();

  bool listen(const ip_addr_t *addr, uint16_t port);
  bool listen(const IPAddress addr, uint16_t port);
  bool listen(const IPv6Address addr, uint16_t port);
  bool listen(uint16_t port);
  bool connect(const ip_addr_t *addr, uint16_t port);
  bool connect(const IPAddress addr, uint16_t port);
  bool connect(const IPv6Address addr, uint16_t port);

  // Join sACN multicast groups for every universe in the configured range.
  // Call after listen() when using multicast sACN sources. Unicast sACN
  // works without it.
  void joinSACNMulticast(int startUniverse, int numUniverses);

  uint8_t *getframe() { return currentframe; }
  operator bool();
  void close();

  void (*frameCallback)();
  inline void setFrameCallback(void (*fptr)()) { frameCallback = fptr; }

  bool addSubArtnet(subArtnet *subart)
  {
    if (numSubArtnet < MAX_SUBARTNET)
    {
      subArtnets[numSubArtnet] = subart;
      subart->subArtnetNum     = numSubArtnet;
      numSubArtnet++;
      subart->_callback_core = CALLBACK_CORE;
      subart->_using_queues  = (_USING_QUEUES == 1);
      return true;
    }
    return false;
  }

  subArtnet *addSubArtnet(int star_universe, uint32_t nb_data,
                          uint32_t nb_data_per_universe,
                          void (*fptr)(void *params))
  {
    return addSubArtnet(star_universe, nb_data, nb_data_per_universe, fptr, NULL);
  }

  subArtnet *addSubArtnet(int star_universe, uint32_t nb_data,
                          uint32_t nb_data_per_universe,
                          void (*fptr)(void *params), uint8_t *leds)
  {
    _udp_task_core = SUBARTNET_CORE;
    if (numSubArtnet < MAX_SUBARTNET)
    {
      subArtnets[numSubArtnet] = (subArtnet *)calloc(sizeof(subArtnet), 1);
      if (!subArtnets[numSubArtnet]) return NULL;
      subArtnets[numSubArtnet]->_initialize(star_universe, nb_data,
                                            nb_data_per_universe, leds);
      subArtnets[numSubArtnet]->subArtnetNum   = numSubArtnet;
      subArtnets[numSubArtnet]->frameCallback  = fptr;
      subArtnets[numSubArtnet]->_callback_core = CALLBACK_CORE;
      subArtnets[numSubArtnet]->_using_queues  = (_USING_QUEUES == 1);
      subArtnets[numSubArtnet]->subartnetglag  = true;
      numSubArtnet++;
      return subArtnets[numSubArtnet - 1];
    }
    return NULL;
  }

  // The patch that listens on this universe, or NULL. Called from the lwIP
  // receive context for every data packet, so it is a plain linear scan.
  subArtnet *findSubArtnet(int universe)
  {
    for (int i = 0; i < numSubArtnet; i++)
    {
      subArtnet *s = subArtnets[i];
      if (universe >= s->startUniverse && universe < s->endUniverse) return s;
    }
    return NULL;
  }

  void setNodeName(String s);

  // ── Node discovery ────────────────────────────────────────────────────────
  // Register a handler for every ArtPollReply seen on the wire. It runs in the
  // lwIP receive context, so it must be short: no Serial, no blocking calls.
  // pkt points at the raw reply (short_name at offset 26, long_name at 44);
  // srcIp is the sender's IPv4 address in network byte order.
  void setPollReplyCallback(void (*fptr)(const uint8_t *pkt, uint16_t len,
                                         uint32_t srcIp));

  // Broadcast an ArtPoll so every node on the segment announces itself.
  // Safe to call from loop(); the send is marshalled onto the tcpip thread.
  bool sendArtPoll();

  subArtnet *subArtnets[MAX_SUBARTNET];
};

#endif // ARTNETESP32_H
