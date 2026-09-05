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
};

struct NodeInfo {
    std::uint64_t nodeId = 0;
    // BasicInformation on endpoint 0.
    std::string vendor;
    std::string product;
    std::string label;
    std::string software;
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
};

struct Callbacks {
    std::function<void(LogLevel, const std::string &)> log;
    // A subscribed OnOff attribute reported a value.
    std::function<void(std::uint64_t nodeId, std::uint16_t endpoint, bool on)> onOff;
    // A node's subscription came up or went down.
    std::function<void(std::uint64_t nodeId, bool reachable)> reachable;
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

    // Commissions the device behind a setup code (an "MT:..." QR payload or a
    // manual pairing code) over the network. One at a time.
    void commission(const std::string &setupCode,
                    std::function<void(std::uint64_t nodeId, CHIP_ERROR)> done);

    // Reads the node's structure: endpoints, device types, server clusters,
    // the labels a bridge attaches to its endpoints.
    void describe(std::uint64_t nodeId, std::function<void(const NodeInfo &, CHIP_ERROR)> done);

    // One wildcard subscription per node on the OnOff attribute, kept alive
    // by the SDK's resubscription policy.
    void subscribeOnOff(std::uint64_t nodeId);

    void setOnOff(std::uint64_t nodeId, std::uint16_t endpoint, bool on,
                  std::function<void(CHIP_ERROR)> done);

    // Runs a task on the Matter thread.
    void post(std::function<void()> task);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

const char *errorText(CHIP_ERROR err);

} // namespace phimatter
