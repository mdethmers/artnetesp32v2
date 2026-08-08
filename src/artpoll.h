   #ifndef ARTNETESP32POLL_H
#define ARTNETESP32POLL_H
#define ARTNET_ETHERNET 0x001
#define ARTNET_ETH 0x002
#define ARTNET_WIFI 0x004
// ARTNET_CONNECT_MODE is no longer used to pick the interface — poll_reply()
// now chooses at runtime. The defines stay so sketches that set them still
// compile.
#ifndef ARTNET_CONNECT_MODE
#define ARTNET_CONNECT_MODE ARTNET_WIFI
#endif
   #include "string.h"

// Pull in the W5500 Ethernet object when the sketch has that library, so the
// reply can report the Ethernet address. Absent it, WiFi and soft-AP are used.
// This is the declaration-only header on purpose — WebServer_ESP32_W5500.h is
// header-only and defines its helpers, so including it here as well as in the
// sketch produces duplicate symbols at link time.
#if __has_include(<w5500/esp32_w5500.h>)
  #include <w5500/esp32_w5500.h>
  #define ARTNET_HAVE_W5500 1
#endif
    constexpr uint16_t DEFAULT_PORT {6454};  // 0x1936

    constexpr uint16_t PROTOCOL_VER {14}; // 0x000E
    constexpr uint8_t ID_LENGTH {8};
    constexpr char ID[ID_LENGTH] {"Art-Net"};
    constexpr float DEFAULT_FPS {40.};


    static constexpr uint8_t NUM_PIXELS_PER_UNIV {170};
    static constexpr size_t NUM_POLLREPLY_PUBLIC_PORT_LIMIT {4};
         String short_name {"Arduino ArtNet"};
        String long_name {"Ardino ArtNet Protocol"};
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


void poll_reply(udp_pcb *pcb,const ip_addr_t *addr) {
            ArtPollReply r;
            for (size_t i = 0; i < ID_LENGTH; i++) r.id[i] = static_cast<uint8_t>(ID[i]);
            r.op_code_l = 0 ; //((uint16_t)OpCode::PollReply >> 0) & 0x00FF;
            r.op_code_h = 0x21; //((uint16_t)OpCode::PollReply >> 8) & 0x00FF;
            // Report whichever interface actually holds an address. This used
            // to be the compile-time ARTNET_CONNECT_MODE switch, which defaults
            // to WiFi — so a node running on Ethernet advertised 0.0.0.0 and
            // the wrong MAC in every reply.
            IPAddress my_ip = WiFi.localIP();
            WiFi.macAddress(r.mac);

            #ifdef ARTNET_HAVE_W5500
            if ((uint32_t)my_ip == 0) {
              my_ip = ETH.localIP();
              ETH.macAddress(r.mac);
            }
            #endif

            if ((uint32_t)my_ip == 0) {   // soft-AP is the last resort
              my_ip = WiFi.softAPIP();
              WiFi.softAPmacAddress(r.mac);
            }
            for (size_t i = 0; i < 4; ++i) r.ip[i] = my_ip[i];
            r.port_l = (DEFAULT_PORT >> 0) & 0xFF;
            r.port_h = (DEFAULT_PORT >> 8) & 0xFF;
            r.ver_h = (PROTOCOL_VER >> 8) & 0x00FF;
            r.ver_l = (PROTOCOL_VER >> 0) & 0x00FF;
            r.oem_h = 0;        // https://github.com/tobiasebsen/ArtNode/blob/master/src/Art-NetOemCodes.h
            r.oem_l = 0xFF;     // OemUnknown
            r.ubea_ver = 0;     // UBEA not programmed
            r.status_1 = 0x00;  // Unknown / Normal
            r.esta_man_l = 0;   // No EATA manufacture code
            r.esta_man_h = 0;   // No ESTA manufacture code
            memset(r.short_name, 0, 18);
            memset(r.long_name, 0, 64);
            memset(r.node_report, 0, 64);
            // Clamp to the field size (leaving room for the terminator) — a
            // node name longer than the field would otherwise run over the
            // fields that follow it in the reply.
            memcpy(r.short_name, short_name.c_str(),
                   short_name.length() < 17 ? short_name.length() : 17);
            memcpy(r.long_name, long_name.c_str(),
                   long_name.length() < 63 ? long_name.length() : 63);
            memcpy(r.node_report, node_report.c_str(),
                   node_report.length() < 63 ? node_report.length() : 63);
            r.num_ports_h = 0;                 // Reserved
            r.num_ports_l = 4;//(callbacks.size() > NUM_POLLREPLY_PUBLIC_PORT_LIMIT) ? NUM_POLLREPLY_PUBLIC_PORT_LIMIT : callbacks.size();
            memset(r.sw_in, 0, 4);
            memset(r.sw_out, 0, 4);
            memset(r.port_types, 0, 4);
            memset(r.good_input, 0, 4);
            memset(r.good_output, 0, 4);
            r.net_sw = 128 & 0x7F;
            r.sub_sw = 16 & 0x0F;
            size_t i = 0;
            for (int i=0;i<4;i++) {
                r.sw_in[i] = 0;//pair.first & 0x0F;
                r.sw_out[i] = i;          // dummy: output port is flexible
                r.port_types[i] = 0xC0;   // I/O available by DMX512
                r.good_input[i] = 0x80;   // Data received without error
                r.good_output[i] = 0x80;  // Data transmitted without error
                //if (++i >= NUM_POLLREPLY_PUBLIC_PORT_LIMIT) break;
            }
            r.sw_video = 0;   // Video display shows local data
            r.sw_macro = 0;   // No support for macro key inputs
            r.sw_remote = 0;  // No support for remote trigger inputs
            memset(r.spare, 0x00, 3);
            r.style = 0x00;  // A DMX to / from Art-Net device
            for (size_t i = 0; i < 4; ++i) r.bind_ip[i] = my_ip[i];
            r.bind_index = 0;
            r.status_2 = 0x08;  // sACN capable
            memset(r.filler, 0x00, 26);
            char jj[12]={'ezerz'};
            //pbuf kk;
            //kk.payload=jj;
            //kk.next=NULL;
            //kk.len=12;//sizeof(ArtPollReply);
            //kk.ref=1;
        
            //Serial.print("%s\n",(char *)r.b);
            pbuf* pbt = pbuf_alloc(PBUF_TRANSPORT, 239, PBUF_RAM);
    if(pbt != NULL) {
        uint8_t* dst = reinterpret_cast<uint8_t*>(pbt->payload);
        memcpy(dst, &r, 239);
        err_t err = udp_sendto(pcb, pbt, addr, 6454);
        pbuf_free(pbt);
        if(err < ERR_OK) {
           Serial.println("pakdd…\n");
        }
        //return len;
    }
    //return 0;
           // udp_send(pcb,&kk);
}
#endif
