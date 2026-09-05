// The Thread network phi's own border router runs, read from otbr-agent.
//
// otbr-agent answers on the console socket ot-ctl uses, one command per
// line, output until "Done" or "Error N: ...". That is enough to learn
// whether a network is up and to fetch its active operational dataset, the
// TLVs a Thread device needs to join it - the one thing a Matter commissioning
// of a Thread device over BLE has to bring along, and the thing another
// controller asks for when it commissions into phi's network.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace phimatter {

struct ThreadNetwork {
    // The socket answered. False with `error` set when otbr-agent is not
    // running (no border router, no dongle) - a normal state, not a fault.
    bool available = false;
    std::string error;
    // "leader", "router", "child", "detached", "disabled".
    std::string state;
    std::string networkName;
    int channel = 0;
    std::string panId;
    std::string extPanId;
    // The active operational dataset as TLV hex, network key included.
    std::string datasetHex;

    // Attached to a network: something a device can join.
    bool attached() const { return state == "leader" || state == "router" || state == "child"; }
    // What a person reads on the instance card.
    std::string summary() const;
};

// Synchronous, with a two-second budget per answer; call it from a thread
// that may block that long.
ThreadNetwork queryThreadNetwork(const std::string &socketPath);

// The dataset's bytes, empty when the hex is not clean.
std::vector<std::uint8_t> bytesFromHex(const std::string &hex);

} // namespace phimatter
