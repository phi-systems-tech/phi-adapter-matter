// The Matter controller behind the phi sidecar: one CHIP stack, one fabric,
// one commissioner. Everything CHIP happens on the Matter thread this class
// starts; the sidecar talks to it through the methods below and hears back
// through callbacks that run on that thread.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <lib/core/CHIPError.h>

namespace phimatter {

enum class LogLevel { Trace, Debug, Info, Warn, Error };

struct EndpointInfo {
    std::uint16_t endpoint = 0;
    std::vector<std::uint32_t> deviceTypes;
    std::vector<std::uint32_t> serverClusters;
    // BridgedDeviceBasicInformation, present on endpoints a bridge stands in for.
    std::string label;
    std::string vendor;
    std::string product;
    // Color Control, when the endpoint serves it: the capabilities bitmap
    // (0x01 hue/saturation, 0x08 xy, 0x10 color temperature) and the
    // temperature range in mireds. Zero when unknown.
    std::uint16_t colorCapabilities = 0;
    std::uint16_t colorTempMinMireds = 0;
    std::uint16_t colorTempMaxMireds = 0;
};

struct NodeInfo {
    std::uint64_t nodeId = 0;
    // BasicInformation on endpoint 0.
    std::string vendor;
    std::string product;
    std::string label;
    std::string software;
    // The address the node answered from, as text; empty when unknown.
    std::string address;
    std::vector<EndpointInfo> endpoints;
};

struct Options {
    // Directory for the fabric: keys, certificates, the node registry.
    std::string stateDir;
    // Directory of PAA root certificates (DER). Empty or missing means the
    // SDK's test roots, which is fine for sample apps and nothing else.
    std::string paaTrustStoreDir;
    // Continue commissioning when device attestation fails.
    bool allowUntrustedAttestation = false;
    // The label this fabric carries on every device, what other admins see
    // in a device's fabric list ("Apple Home", "Tuya"). At most 32 bytes.
    std::string fabricLabel;
    // UDP port the controller listens on; 0 means the Matter default (5540).
    // Two cores on one host need two ports.
    std::uint16_t listenPort = 0;
    // HCI adapter index for BLE commissioning (hci0 -> 0). Negative
    // disables BLE: commissioning then reaches only devices already on
    // an IP network, which a device out of its box is not. Which
    // controller that is depends on the machine - built in on one, a USB
    // dongle on the next - so it is a setting rather than a default.
    int bleAdapter = -1;
};

// One reported attribute, reduced to what a channel needs.
struct AttributeValue {
    bool isNull = false;
    bool boolean = false;
    double number = 0.0;
};

struct Callbacks {
    std::function<void(LogLevel, const std::string &)> log;
    // A subscribed attribute reported a value.
    std::function<void(std::uint64_t nodeId, std::uint16_t endpoint, std::uint32_t cluster, std::uint32_t attribute,
                       const AttributeValue &value)> attribute;
    // A node's subscription came up or went down.
    std::function<void(std::uint64_t nodeId, bool reachable)> reachable;
    // The node's endpoint list changed: a bridge gained or lost a device.
    std::function<void(std::uint64_t nodeId)> topologyChanged;
};

class Controller
{
public:
    Controller();
    ~Controller();

    Controller(const Controller &) = delete;
    Controller &operator=(const Controller &) = delete;

    // Brings the stack up and starts the Matter thread. Runs on the caller's
    // thread; nothing else may be called before it returns true.
    bool start(const Options &options, Callbacks callbacks, std::string *error);
    // Tears the stack down within roughly the given budget.
    void stop(int budgetMs);

    void setAllowUntrustedAttestation(bool allow);

    // Node ids known to this fabric, from the registry.
    std::vector<std::uint64_t> nodes() const;
    // The compressed fabric id as 16 hex digits, the fabric's public name.
    std::string compressedFabricId() const;

    // Writes the node's own label (Basic Information, NodeLabel): the name
    // the device itself carries from then on. At most 32 bytes.
    void setNodeLabel(std::uint64_t nodeId, const std::string &label, std::function<void(CHIP_ERROR)> done);

    // Names written to devices, kept in the registry so that lists can show
    // them without a read; keyed by the device id ("n1-e0").
    void setDeviceName(const std::string &deviceId, const std::string &name);
    std::string deviceName(const std::string &deviceId) const;

    // Writes the fabric label to the node (Operational Credentials,
    // UpdateFabricLabel). Done after commissioning and whenever it changes.
    void setFabricLabel(std::uint64_t nodeId, const std::string &label, std::function<void(CHIP_ERROR)> done);

    // Commissions the device behind a setup code (an "MT:..." QR payload or a
    // manual pairing code) over the network. One at a time. A Thread
    // operational dataset (TLV bytes), when given, is handed to a device
    // that has a Thread radio to configure; devices on Wi-Fi or Ethernet
    // never see it.
    void commission(const std::string &setupCode, std::vector<std::uint8_t> threadDataset,
                    std::function<void(std::uint64_t nodeId, CHIP_ERROR)> done);

    // Reads the node's structure: endpoints, device types, server clusters,
    // the labels a bridge attaches to its endpoints.
    void describe(std::uint64_t nodeId, std::function<void(const NodeInfo &, CHIP_ERROR)> done);

    // One wildcard subscription per node on the attributes channels are made
    // of, kept alive by the SDK's resubscription policy.
    void subscribe(std::uint64_t nodeId);

    void setOnOff(std::uint64_t nodeId, std::uint16_t endpoint, bool on,
                  std::function<void(CHIP_ERROR)> done);
    // Level 0..254 with OnOff coupled, the way a dimmer expects it.
    void setLevel(std::uint64_t nodeId, std::uint16_t endpoint, std::uint8_t level,
                  std::function<void(CHIP_ERROR)> done);
    // Color temperature in mireds, the cluster's own unit.
    void setColorTemperature(std::uint64_t nodeId, std::uint16_t endpoint, std::uint16_t mireds,
                             std::function<void(CHIP_ERROR)> done);
    // Hue and saturation on the cluster's 0..254 scale.
    void setHueSaturation(std::uint64_t nodeId, std::uint16_t endpoint, std::uint8_t hue, std::uint8_t saturation,
                          std::function<void(CHIP_ERROR)> done);

    // Opens the device's commissioning window for another ecosystem: a fresh
    // passcode and discriminator, valid for the given seconds (180..900).
    // Delivers the manual pairing code and the QR payload to enter there.
    void share(std::uint64_t nodeId, std::uint16_t timeoutSeconds,
               std::function<void(const std::string &manualCode, const std::string &qrCode, CHIP_ERROR)> done);

    // Removes this fabric from the device and forgets the node. The node is
    // forgotten either way; the error says whether the device took part.
    // A device that did not answer keeps the fabric until it is reset.
    void remove(std::uint64_t nodeId, std::function<void(CHIP_ERROR)> done);

    // Runs a task on the Matter thread.
    void post(std::function<void()> task);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

const char *errorText(CHIP_ERROR err);

} // namespace phimatter
