#ifndef ARTNETESP32POLL_H
#define ARTNETESP32POLL_H
// Included from artnetESP32V2.cpp only. It builds the ArtPollReply and is
// called from the lwIP receive callback, so it must not log, allocate more
// than the one pbuf, or touch the Arduino WiFi/Ethernet objects.

#define ARTNET_ETHERNET 0x001
#define ARTNET_ETH      0x002
#define ARTNET_WIFI     0x004
// ARTNET_CONNECT_MODE is no longer used: the reply reports the interface the
// poll arrived on. The defines stay so sketches that set them still compile.
#ifndef ARTNET_CONNECT_MODE
#define ARTNET_CONNECT_MODE ARTNET_WIFI
#endif

#include "string.h"

constexpr uint16_t DEFAULT_PORT  {6454};  // 0x1936
constexpr uint16_t PROTOCOL_VER  {14};    // 0x000E
constexpr uint8_t  ID_LENGTH     {8};
constexpr char     ID[ID_LENGTH] {"Art-Net"};
constexpr float    DEFAULT_FPS   {40.};

static constexpr uint8_t NUM_PIXELS_PER_UNIV {170};
static constexpr size_t  NUM_POLLREPLY_PUBLIC_PORT_LIMIT {4};

String short_name  {"Arduino ArtNet"};
String long_name   {"Ardino ArtNet Protocol"};
String node_report {""};

union ArtPollReply {
  struct {
    uint8_t id[8];
    uint8_t op_code_l;
    uint8_t op_code_h;
    uint8_t ip[4];
    uint8_t port_l;
    uint8_t port_h;
    uint8_t ver_h;
    uint8_t ver_l;
    uint8_t net_sw;
    uint8_t sub_sw;
    uint8_t oem_h;
    uint8_t oem_l;
    uint8_t ubea_ver;
    uint8_t status_1;
    uint8_t esta_man_l;
    uint8_t esta_man_h;
    uint8_t short_name[18];
    uint8_t long_name[64];
    uint8_t node_report[64];
    uint8_t num_ports_h;
    uint8_t num_ports_l;
    uint8_t port_types[NUM_POLLREPLY_PUBLIC_PORT_LIMIT];
    uint8_t good_input[NUM_POLLREPLY_PUBLIC_PORT_LIMIT];
    uint8_t good_output[NUM_POLLREPLY_PUBLIC_PORT_LIMIT];
    uint8_t sw_in[NUM_POLLREPLY_PUBLIC_PORT_LIMIT];
    uint8_t sw_out[NUM_POLLREPLY_PUBLIC_PORT_LIMIT];
    uint8_t sw_video;
    uint8_t sw_macro;
    uint8_t sw_remote;
    uint8_t spare[3];
    uint8_t style;
    uint8_t mac[6];
    uint8_t bind_ip[4];
    uint8_t bind_index;
    uint8_t status_2;
    uint8_t filler[26];
  };
  uint8_t b[239];
};

// Broadcast an ArtPollReply, as the Art-Net spec asks. The address and MAC
// come from the interface the poll arrived on, which is valid inside the
// receive callback and needs no call into the Arduino network objects.
static void poll_reply(udp_pcb *pcb)
{
  struct netif *nif = ip_current_netif();
  if (!nif) return;

  ArtPollReply r;
  memset(&r, 0, sizeof(r));

  for (size_t i = 0; i < ID_LENGTH; i++) r.id[i] = static_cast<uint8_t>(ID[i]);
  r.op_code_l = 0x00;   // OpPollReply = 0x2100, little-endian on the wire
  r.op_code_h = 0x21;

  memcpy(r.ip, &ip_2_ip4(&nif->ip_addr)->addr, 4);
  memcpy(r.mac, nif->hwaddr, 6);
  memcpy(r.bind_ip, r.ip, 4);

  r.port_l = (DEFAULT_PORT >> 0) & 0xFF;
  r.port_h = (DEFAULT_PORT >> 8) & 0xFF;
  r.ver_h  = (PROTOCOL_VER >> 8) & 0xFF;
  r.ver_l  = (PROTOCOL_VER >> 0) & 0xFF;
  r.oem_h  = 0;
  r.oem_l  = 0xFF;      // OemUnknown
  r.ubea_ver   = 0;
  r.status_1   = 0x00;
  r.esta_man_l = 0;
  r.esta_man_h = 0;

  // Clamp to the field size, leaving room for the terminator.
  memcpy(r.short_name,  short_name.c_str(),  short_name.length()  < 17 ? short_name.length()  : 17);
  memcpy(r.long_name,   long_name.c_str(),   long_name.length()   < 63 ? long_name.length()   : 63);
  memcpy(r.node_report, node_report.c_str(), node_report.length() < 63 ? node_report.length() : 63);

  r.num_ports_h = 0;
  r.num_ports_l = 4;
  r.net_sw = 128 & 0x7F;
  r.sub_sw = 16 & 0x0F;
  for (int i = 0; i < 4; i++)
  {
    r.sw_in[i]       = 0;
    r.sw_out[i]      = i;      // dummy: output port is flexible
    r.port_types[i]  = 0xC0;   // I/O available by DMX512
    r.good_input[i]  = 0x80;   // Data received without error
    r.good_output[i] = 0x80;   // Data transmitted without error
  }
  r.sw_video   = 0;
  r.sw_macro   = 0;
  r.sw_remote  = 0;
  r.style      = 0x00;   // A DMX to / from Art-Net device
  r.bind_index = 0;
  r.status_2   = 0x08;   // sACN capable

  pbuf *pbt = pbuf_alloc(PBUF_TRANSPORT, sizeof(r.b), PBUF_RAM);
  if (pbt == NULL) return;
  memcpy(pbt->payload, r.b, sizeof(r.b));
  ip_set_option(pcb, SOF_BROADCAST);
  udp_sendto(pcb, pbt, IP_ADDR_BROADCAST, DEFAULT_PORT);
  pbuf_free(pbt);
}
#endif
