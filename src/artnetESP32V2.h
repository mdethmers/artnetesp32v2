#ifndef ARTNETESP32_H
#define ARTNETESP32_H
#include "WiFi.h"
#include "IPAddress.h"
#include "IPv6Address.h"
#include "Print.h"
#include "Stream.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <functional>
#include "string.h"
extern "C"
{
#include "esp_netif.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
}

#include "lwip/priv/tcpip_priv.h"
#include "lwip/igmp.h"

// CONFIG_UDP_RECVMBOX_SIZE=6
// CONFIG_LWIP_MAX_UDP_PCBS

struct udp_pcb;
struct pbuf;
struct netif;

typedef struct
{
    pbuf *pb;
    int universe;
} lwip_event_packet_t;

#define ART_DMX_START    18
#define BUFFER_SIZE      512
#define MAX_SUBARTNET    20
#define NB_MAX_BUFFER    10

// ── sACN / E1.31 constants ────────────────────────────────────────────────────
#define SACN_PORT           5568
#define SACN_HEADER_SIZE    126   // bytes before DMX payload in E1.31
#define SACN_UNIVERSE_HIGH  113   // big-endian universe MSB offset
#define SACN_UNIVERSE_LOW   114   // big-endian universe LSB offset
// Framing layer opcode at offsets 40-41 (big-endian): 0x0088 = DMP layer
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
#define FRAME_END   1
#define FRAME_START 2
#ifndef _SYNC_FRAME_
#define _SYNC_FRAME_ FRAME_END
#endif

#ifndef NB_FRAMES_DELTA
#define NB_FRAMES_DELTA 100
#endif

// ── Protocol mode ─────────────────────────────────────────────────────────────
#define PROTOCOL_ARTNET 0
#define PROTOCOL_SACN   1
#define PROTOCOL_BOTH   2

static xQueueHandle _show_queue[MAX_SUBARTNET];
static xQueueHandle _udp_queue;
static volatile TaskHandle_t _udp_task_handle = NULL;

static void _udp_task_subrarnet(void *pvParameters);
static void _udp_task_subrarnet_handle(void *pvParameters);

// ─────────────────────────────────────────────────────────────────────────────
class subArtnet
{
public:
  int startUniverse, endUniverse, nbDataPerUniverse, nbNeededUniverses,
      nb_frames_lost, nb_frames, previous_lost, nb_frame_double;
  uint8_t *buffers[10];
  uint8_t  currentframenumber;
  uint8_t  nbOfBuffers = 2;
  uint8_t  nbBufferled;
  uint8_t *data;
  int      previousUniverse;
  // Adaptive end-of-frame detection
  int      observedEnd;
  int      highestSeenThisFrame;
  size_t   len;
  size_t   tmp_len;
  bool     subartnetglag;
  void   (*frameCallback)(void *params);
  bool     new_frame  = false;
  bool     frame_disp = false;
  int      subArtnetNum;
  uint32_t _nb_data;
  long     time1, time2;
  uint8_t *offset, *offset2;
  uint8_t  _callback_core = CALLBACK_CORE;

  volatile xSemaphoreHandle subArtnet_sem = NULL;

  subArtnet(int star_universe, uint32_t nb_data, uint32_t nb_data_per_universe);
  void createBuffers(uint8_t *leds);
  void _initialize(int star_universe, uint32_t nb_data, uint32_t nb_data_per_universe, uint8_t *leds);
  ~subArtnet();

  // ── Universe handler (called from the UDP task) ───────────────────────────
  void handleUniverse(lwip_event_packet_t *e)
  {
    Serial.printf("sACN handleUniverse subart=%d start=%d end=%d recv=%d len=%u new_frame=%d prev=%d highestSeen=%d\n",
                  subArtnetNum, startUniverse, endUniverse, e->universe,
                  (unsigned)e->pb->len, new_frame, previousUniverse,
                  highestSeenThisFrame);

    if (e->universe == startUniverse)
    {
      // Flush in-progress frame if sender shrank universe count
      if (new_frame)
      {
        uint8_t *d = buffers[currentframenumber];
        currentframenumber = (currentframenumber + 1) % nbOfBuffers;
        offset    = buffers[currentframenumber];
        new_frame = false;

        #ifdef _USING_QUEUES
          if (xQueueSend(_show_queue[subArtnetNum], &d, 0) != pdTRUE)
            nb_frames_lost++;
        #else
          nb_frames++;
          if (frameCallback) frameCallback((void *)this);
        #endif
      }

      // Adapt observedEnd from last frame
      if (highestSeenThisFrame >= startUniverse)
      {
        observedEnd = highestSeenThisFrame;
        if (observedEnd > endUniverse - 1)
          observedEnd = endUniverse - 1;
      }
      highestSeenThisFrame = startUniverse - 1;

      offset           = buffers[currentframenumber];
      new_frame        = true;
      previousUniverse = startUniverse - 1;
    }

    if (e->universe > highestSeenThisFrame)
      highestSeenThisFrame = e->universe;

    if (!new_frame) return;

    if (e->universe == previousUniverse + 1)
    {
      previousUniverse++;
      memcpy(offset, e->pb->payload, e->pb->len);
      offset += e->pb->len;

      // Flush on adaptive observedEnd OR configured hard cap
      if (e->universe == observedEnd || e->universe == endUniverse - 1)
      {
        data               = buffers[currentframenumber];
        currentframenumber = (currentframenumber + 1) % nbOfBuffers;
        offset             = buffers[currentframenumber];
        new_frame          = false;

        #ifdef _USING_QUEUES
          if (xQueueSend(_show_queue[subArtnetNum], &data, 0) != pdTRUE)
            nb_frames_lost++;
        #else
          nb_frames++;
          if (frameCallback) frameCallback((void *)this);
        #endif
      }
    }
    else
    {
      Serial.printf("sACN universe mismatch subart=%d got=%d expected=%d\n",
                    subArtnetNum, e->universe, previousUniverse + 1);
      new_frame = false;
    }
  }

  uint8_t *getData();

  void setFrameCallback(void (*fptr)(void *params))
  {
    frameCallback = fptr;
  }

  bool _using_queues;
};

// ─────────────────────────────────────────────────────────────────────────────
class artnetESP32V2
{
protected:
  udp_pcb  *_pcb;        // ArtNet UDP PCB  (port 6454)
  udp_pcb  *_sacn_pcb;   // sACN  UDP PCB  (port 5568)
  bool      _connected;
  esp_err_t _lastErr;

  bool _init();
  bool _initSACN();      // bind the sACN PCB

public:
  int      num_universes, numSubArtnet = 0;
  uint8_t *artnetleds1, *buffer2;
  uint8_t *buffers[10];
  uint8_t  currentframenumber;
  uint8_t  nbOfBuffers = 2;
  uint8_t  _udp_task_core = SUBARTNET_CORE;

  uint8_t *currentframe;
  uint32_t pixels_per_universe, nbPixels, nbPixelsPerUniverse,
           nbNeededUniverses, startuniverse, enduniverse, nbframes, nbframeslost;

  // Protocol mode: PROTOCOL_ARTNET (0), PROTOCOL_SACN (1), PROTOCOL_BOTH (2)
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
  // Call this after listen() when using multicast sACN sources.
  // Many software packages (e.g. MA3, LightKey) send unicast — multicast join
  // is then not required but harmless.
  void joinSACNMulticast(int startUniverse, int numUniverses);

  uint8_t *getframe() { return currentframe; }
  operator bool();
  void close();

  void (*frameCallback)();
  inline void setFrameCallback(void (*fptr)())
  {
    frameCallback = fptr;
  }

  bool addSubArtnet(subArtnet *subart)
  {
    #ifdef UNIQUE_SUBARTNET
    Serial.printf("delta %d \n", NB_FRAMES_DELTA);
    #else
    Serial.printf("jkjcvbcvbcvbcvkjk\n");
    #endif
    if (numSubArtnet < MAX_SUBARTNET)
    {
      subArtnets[numSubArtnet] = subart;
      subart->subArtnetNum     = numSubArtnet;
      numSubArtnet++;
      subart->_callback_core = CALLBACK_CORE;
      #ifdef _USING_QUEUES
      subart->_using_queues = true;
      #else
      subart->_using_queues = false;
      #endif
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
      subArtnets[numSubArtnet]->_initialize(star_universe, nb_data,
                                            nb_data_per_universe, leds);
      subArtnets[numSubArtnet]->subArtnetNum  = numSubArtnet;
      subArtnets[numSubArtnet]->frameCallback = fptr;
      subArtnets[numSubArtnet]->_callback_core = CALLBACK_CORE;
      #if _USING_QUEUES == 1
        subArtnets[numSubArtnet]->_using_queues = true;
      #else
        subArtnets[numSubArtnet]->_using_queues = false;
      #endif
      subArtnets[numSubArtnet]->subartnetglag = true;
      numSubArtnet++;
      return subArtnets[numSubArtnet - 1];
    }
    return NULL;
  }

  void setNodeName(String s);

  subArtnet *subArtnets[MAX_SUBARTNET];
};

// ─────────────────────────────────────────────────────────────────────────────
// UDP task: receives from _udp_queue, dispatches to subArtnet handlers
// ─────────────────────────────────────────────────────────────────────────────
static void _udp_task_subrarnet(void *pvParameters)
{
  lwip_event_packet_t *e = NULL;
  ESP_LOGI("ARTNETESP32", "Start listening task");
  artnetESP32V2 *artnet = (artnetESP32V2 *)pvParameters;

  for (int i = 0; i < artnet->numSubArtnet; i++)
  {
    subArtnet *s = artnet->subArtnets[i];
    ESP_LOGI("ARTNETESP32",
             "subArtnet nr:%d start universe:%d Nb Universes: %d",
             s->subArtnetNum, s->startUniverse, s->nbNeededUniverses);
  }

  for (;;)
  {
    if (xQueueReceive(_udp_queue, &e, portMAX_DELAY) == pdTRUE)
    {
      if (!e->pb) { free((void *)e); continue; }

      e->pb->payload = (uint8_t *)e->pb->payload + ART_DMX_START;

      #ifndef UNIQUE_SUBARTNET
      for (int i = 0; i < artnet->numSubArtnet; i++)
      {
        subArtnet *s = artnet->subArtnets[i];
        if (s->startUniverse <= e->universe &&
            (s->endUniverse - 1) >= e->universe)
        {
          e->pb->len = (e->pb->len - ART_DMX_START < (uint16_t)s->nbDataPerUniverse)
                     ? (e->pb->len - ART_DMX_START)
                     : (uint16_t)s->nbDataPerUniverse;
          s->handleUniverse(e);
        }
      }
      #else
      subArtnet *s = artnet->subArtnets[0];
      e->pb->len = (e->pb->len - ART_DMX_START < (uint16_t)s->nbDataPerUniverse)
                 ? (e->pb->len - ART_DMX_START)
                 : (uint16_t)s->nbDataPerUniverse;
      s->handleUniverse(e);
      #endif

      pbuf_free(e->pb);
      free((void *)e);
    }
  }
  _udp_task_handle = NULL;
  vTaskDelete(NULL);
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-subArtnet callback task
// ─────────────────────────────────────────────────────────────────────────────
static void _udp_task_subrarnet_handle(void *pvParameters)
{
  subArtnet *subartnet = (subArtnet *)pvParameters;
  uint8_t   *data      = NULL;
  ESP_LOGV("ARTNETESP32", "_udp_task_subrarnet_handle set on core %d",
           xPortGetCoreID());

  #if CORE_DEBUG_LEVEL >= 2
  long t1, t2;
  #endif

  for (;;)
  {
    if (xQueueReceive(_show_queue[subartnet->subArtnetNum], &data,
                      portMAX_DELAY) == pdTRUE)
    {
      #if CORE_DEBUG_LEVEL >= 2
      t1 = ESP.getCycleCount();
      #endif

      subartnet->data = data;
      subartnet->nb_frames++;
      if (subartnet->frameCallback)
        subartnet->frameCallback((void *)subartnet);

      #if CORE_DEBUG_LEVEL >= 2
      t2 = ESP.getCycleCount() - t1;
      if (NB_MAX_BUFFER -
          uxQueueSpacesAvailable(_show_queue[subartnet->subArtnetNum]) > 0)
      {
        ESP_LOGD("ARTNETESP32", "encore %d Frame:%d %f",
                 NB_MAX_BUFFER -
                 uxQueueSpacesAvailable(_show_queue[subartnet->subArtnetNum]),
                 subartnet->nb_frames, (float)t2 / 240000);
        subartnet->nb_frame_double++;
      }
      if ((subartnet->nb_frames) % NB_FRAMES_DELTA == 0)
      {
        subartnet->time2 = millis();
        ESP_LOGI("ARTNETESP32",
                 "SUBARTNET:%d frames:%d lost:%d delta:%d pct:%.2f fps:%.2f dbl:%d",
                 subartnet->subArtnetNum, subartnet->nb_frames,
                 subartnet->nb_frames_lost - 1,
                 subartnet->nb_frames_lost - subartnet->previous_lost,
                 (float)(100 * (subartnet->nb_frames_lost - 1)) /
                     (subartnet->nb_frames_lost + subartnet->nb_frames - 1),
                 (float)(1000 * NB_FRAMES_DELTA /
                     ((subartnet->time2 - subartnet->time1) / 1)),
                 subartnet->nb_frame_double);
        subartnet->time1    = subartnet->time2;
        subartnet->previous_lost = subartnet->nb_frames_lost;
      }
      #endif
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
    _udp_queue = xQueueCreate(128, sizeof(lwip_event_packet_t *));
    if (!_udp_queue) return false;
  }
  for (int i = 0; i < p->numSubArtnet; i++)
  {
    if (!_show_queue[i])
    {
      _show_queue[i] = xQueueCreate(NB_MAX_BUFFER, sizeof(uint8_t *));
      if (!_show_queue[i])
      {
        ESP_LOGD("ARTNETESP32", "SHOW QUEUE %d NOT CREATED", i);
        return false;
      }
      ESP_LOGI("ARTNETESP32", "QUEUES CREATED");
    }
  }
  if (!_udp_task_handle)
  {
    xTaskCreateUniversal(_udp_task_subrarnet, "_udp_task_subrarnet", 4096, p,
                         CONFIG_ARDUINO_UDP_TASK_PRIORITY,
                         (TaskHandle_t *)&_udp_task_handle, SUBARTNET_CORE);
    if (!_udp_task_handle)
    {
      ESP_LOGI("ARTNETESP32", "no task handle");
      return false;
    }
  }
  return true;
}

#endif // ARTNETESP32_H
