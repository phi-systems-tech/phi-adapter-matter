// phi_adapter_matter_ipc: the Matter controller as a phi adapter sidecar.
//
// One instance is one fabric. Devices are commissioned over the network with a
// setup code, every endpoint that serves OnOff becomes a phi device with a
// power channel, and one subscription per node keeps the state current.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>

#include <json/json.h>

#include "phi/adapter/sdk/sidecar.h"

#include "controller.h"

namespace phi = phicore::adapter::sdk;
namespace v1 = phicore::adapter::v1;

namespace {

constexpr const char kPluginType[] = "matter";
constexpr const char kDisplayName[] = "Matter";
constexpr const char kOnOffChannel[] = "onoff";
constexpr const char kCommissionAction[] = "commission";
constexpr const char kPairingCodeField[] = "pairingCode";
constexpr const char kAllowUntrustedField[] = "allowUntrustedAttestation";
constexpr const char kDefaultPaaDir[] = "/usr/share/phi/matter/paa-root-certs";
constexpr int kStopBudgetMs = 1500;

constexpr const char kIconSvg[] =
    "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 24 24\" width=\"24\" height=\"24\" fill=\"none\" "
    "stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\" stroke-linejoin=\"round\" role=\"img\" "
    "aria-label=\"Matter\">"
    "<path d=\"M12 3v9\"/><path d=\"M12 12l7.8 4.5\"/><path d=\"M12 12L4.2 16.5\"/>"
    "<circle cx=\"12\" cy=\"3\" r=\"1.6\"/><circle cx=\"19.8\" cy=\"16.5\" r=\"1.6\"/><circle cx=\"4.2\" cy=\"16.5\" r=\"1.6\"/>"
    "<circle cx=\"12\" cy=\"12\" r=\"2.2\"/></svg>";

std::atomic_bool g_running{true};

void handleSignal(int)
{
    g_running.store(false);
}

std::int64_t nowMs()
{
    const auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

std::string jsonQuoted(std::string_view text)
{
    const Json::Value value{std::string(text)};
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    return Json::writeString(builder, value);
}

Json::Value parseObject(const std::string &text)
{
    Json::Value root;
    if (text.empty())
        return Json::Value(Json::objectValue);
    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    std::string error;
    if (!reader->parse(text.data(), text.data() + text.size(), &root, &error) || !root.isObject())
        return Json::Value(Json::objectValue);
    return root;
}

std::string trimmed(std::string text)
{
    const auto notSpace = [](unsigned char c) { return !std::isspace(c); };
    text.erase(text.begin(), std::find_if(text.begin(), text.end(), notSpace));
    text.erase(std::find_if(text.rbegin(), text.rend(), notSpace).base(), text.end());
    return text;
}

// Where the fabric lives. Core hands the sidecar nothing but its socket, which
// sits in <tenant data dir>/ipc; the fabric is tenant state, so it goes beside
// it.
std::string stateRoot(const std::string &socketPath)
{
    if (const char *env = std::getenv("PHI_ADAPTER_STATE_DIR"); env && *env)
        return env;
    const std::filesystem::path socket(socketPath);
    return (socket.parent_path().parent_path() / "matter").string();
}

std::string sanitized(const std::string &text)
{
    std::string out;
    for (const char c : text)
        out.push_back((std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_') ? c : '_');
    return out.empty() ? std::string("default") : out;
}

phi::LogLevel toSdkLevel(phimatter::LogLevel level)
{
    switch (level) {
    case phimatter::LogLevel::Trace: return phi::LogLevel::Trace;
    case phimatter::LogLevel::Debug: return phi::LogLevel::Debug;
    case phimatter::LogLevel::Info: return phi::LogLevel::Info;
    case phimatter::LogLevel::Warn: return phi::LogLevel::Warn;
    case phimatter::LogLevel::Error: return phi::LogLevel::Error;
    }
    return phi::LogLevel::Info;
}

// Matter device types, the ones that decide a phi device class.
enum DeviceType : std::uint32_t {
    OnOffLight = 0x0100,
    DimmableLight = 0x0101,
    ColorTemperatureLight = 0x010C,
    ExtendedColorLight = 0x010D,
    OnOffPlugInUnit = 0x010A,
    DimmablePlugInUnit = 0x010B,
};

v1::DeviceClass deviceClassFor(const std::vector<std::uint32_t> &deviceTypes)
{
    for (const std::uint32_t type : deviceTypes) {
        switch (type) {
        case OnOffLight:
        case DimmableLight:
        case ColorTemperatureLight:
        case ExtendedColorLight:
            return v1::DeviceClass::Light;
        case OnOffPlugInUnit:
        case DimmablePlugInUnit:
            return v1::DeviceClass::Plug;
        default:
            break;
        }
    }
    return v1::DeviceClass::Switch;
}

constexpr std::uint32_t kOnOffClusterId = 0x0006;

std::string deviceExternalId(std::uint64_t nodeId, std::uint16_t endpoint)
{
    char text[48];
    std::snprintf(text, sizeof(text), "n%llx-e%u", static_cast<unsigned long long>(nodeId), static_cast<unsigned>(endpoint));
    return text;
}

bool parseDeviceExternalId(const std::string &id, std::uint64_t *nodeId, std::uint16_t *endpoint)
{
    unsigned long long node = 0;
    unsigned ep = 0;
    if (std::sscanf(id.c_str(), "n%llx-e%u", &node, &ep) != 2)
        return false;
    *nodeId = node;
    *endpoint = static_cast<std::uint16_t>(ep);
    return true;
}

class MatterInstance final : public phi::AdapterInstance
{
public:
    explicit MatterInstance(std::string stateRoot) : m_stateRoot(std::move(stateRoot)) {}

protected:
    bool start() override
    {
        applyConfig();

        phimatter::Options options;
        options.stateDir = (std::filesystem::path(m_stateRoot) / sanitized(externalId())).string();
        options.paaTrustStoreDir = kDefaultPaaDir;
        if (const char *env = std::getenv("PHI_MATTER_PAA_TRUST_STORE"); env && *env)
            options.paaTrustStoreDir = env;
        options.allowUntrustedAttestation = m_allowUntrusted;

        phimatter::Callbacks callbacks;
        callbacks.log = [this](phimatter::LogLevel level, const std::string &message) {
            log(toSdkLevel(level), phi::LogCategory::Protocol, message, {}, "matter.chip");
        };
        callbacks.onOff = [this](std::uint64_t nodeId, std::uint16_t endpoint, bool on) {
            sendChannelStateUpdated(deviceExternalId(nodeId, endpoint), kOnOffChannel, v1::ScalarValue(on), nowMs());
        };
        callbacks.topologyChanged = [this](std::uint64_t nodeId) {
            char text[80];
            std::snprintf(text, sizeof(text), "node 0x%llx: endpoint list changed, reading it again",
                          static_cast<unsigned long long>(nodeId));
            log(phi::LogLevel::Info, phi::LogCategory::Device, text, {}, "matter.node.topology");
            describeAndPublish(nodeId);
        };
        callbacks.reachable = [this](std::uint64_t nodeId, bool reachable) {
            char text[80];
            std::snprintf(text, sizeof(text), "node 0x%llx %s", static_cast<unsigned long long>(nodeId),
                          reachable ? "reachable" : "unreachable");
            log(reachable ? phi::LogLevel::Info : phi::LogLevel::Warn, phi::LogCategory::Network, text, {},
                "matter.node.reachable");
        };

        std::string error;
        if (!m_controller.start(options, std::move(callbacks), &error)) {
            sendError(phi::LogCategory::Lifecycle, "Matter stack failed to start: %1", phi::ScalarList{error},
                      "matter.lifecycle.start.failed");
            return false;
        }
        m_started = true;

        sendConnectionStateChanged(true);
        for (const std::uint64_t nodeId : m_controller.nodes())
            adoptNode(nodeId);
        return true;
    }

    void stop() override
    {
        if (m_started) {
            m_controller.stop(kStopBudgetMs);
            m_started = false;
        }
    }

    void onConfigChanged(const phi::ConfigChangedRequest &) override
    {
        applyConfig();
        if (m_started)
            m_controller.setAllowUntrustedAttestation(m_allowUntrusted);
    }

    void onChannelInvoke(const phi::ChannelInvokeRequest &request) override
    {
        std::uint64_t nodeId = 0;
        std::uint16_t endpoint = 0;
        if (request.channelExternalId != kOnOffChannel
            || !parseDeviceExternalId(request.deviceExternalId, &nodeId, &endpoint)) {
            submit(makeResponse(request.cmdId, v1::CmdStatus::NotSupported, "Unknown Matter channel"));
            return;
        }
        if (!request.hasScalarValue || !std::holds_alternative<bool>(request.value)) {
            submit(makeResponse(request.cmdId, v1::CmdStatus::InvalidArgument, "OnOff wants a boolean"));
            return;
        }
        if (!m_started) {
            submit(makeResponse(request.cmdId, v1::CmdStatus::TemporarilyOffline, "Matter stack is not running"));
            return;
        }
        const bool on = std::get<bool>(request.value);
        const phi::CmdId cmdId = request.cmdId;
        const std::string device = request.deviceExternalId;
        m_controller.setOnOff(nodeId, endpoint, on, [this, cmdId, device, on](CHIP_ERROR err) {
            if (err == CHIP_NO_ERROR) {
                v1::CmdResponse resp = makeResponse(cmdId, v1::CmdStatus::Success, {});
                resp.finalValue = v1::ScalarValue(on);
                submit(std::move(resp));
                sendChannelStateUpdated(device, kOnOffChannel, v1::ScalarValue(on), nowMs());
            } else {
                submit(makeResponse(cmdId, v1::CmdStatus::Failure, phimatter::errorText(err)));
            }
        });
    }

    void onAdapterActionInvoke(const phi::AdapterActionInvokeRequest &request) override
    {
        v1::ActionResponse resp;
        resp.id = request.cmdId;
        resp.tsMs = nowMs();

        if (request.actionId != kCommissionAction) {
            resp.status = v1::CmdStatus::NotSupported;
            resp.error = "Unsupported action";
            submitAction(std::move(resp));
            return;
        }
        const Json::Value params = parseObject(request.paramsJson);
        const std::string code = trimmed(params.get(kPairingCodeField, "").asString());
        if (code.empty()) {
            resp.status = v1::CmdStatus::InvalidArgument;
            resp.error = "Enter the device's pairing code first";
            submitAction(std::move(resp));
            return;
        }
        if (!m_started) {
            resp.status = v1::CmdStatus::TemporarilyOffline;
            resp.error = "Matter stack is not running";
            submitAction(std::move(resp));
            return;
        }

        const phi::CmdId cmdId = request.cmdId;
        m_controller.commission(code, [this, cmdId](std::uint64_t nodeId, CHIP_ERROR err) {
            v1::ActionResponse done;
            done.id = cmdId;
            done.tsMs = nowMs();
            if (err != CHIP_NO_ERROR) {
                done.status = v1::CmdStatus::Failure;
                done.error = std::string("Commissioning failed: ") + phimatter::errorText(err);
                submitAction(std::move(done));
                return;
            }
            done.status = v1::CmdStatus::Success;
            done.resultType = v1::ActionResultType::String;
            char text[64];
            std::snprintf(text, sizeof(text), "Commissioned as node 0x%llx", static_cast<unsigned long long>(nodeId));
            done.resultValue = v1::ScalarValue(std::string(text));
            // The code is single-use; clear it from the form.
            done.formValuesJson = std::string("{\"") + kPairingCodeField + "\":\"\"}";
            submitAction(std::move(done));
            adoptNode(nodeId);
        });
    }

    void onDeviceNameUpdate(const phi::DeviceNameUpdateRequest &request) override
    {
        submit(makeResponse(request.cmdId, v1::CmdStatus::NotImplemented, "Renaming is not supported yet"));
    }

    void onDeviceEffectInvoke(const phi::DeviceEffectInvokeRequest &request) override
    {
        submit(makeResponse(request.cmdId, v1::CmdStatus::NotSupported, "Effects are not supported"));
    }

    void onSceneInvoke(const phi::SceneInvokeRequest &request) override
    {
        submit(makeResponse(request.cmdId, v1::CmdStatus::NotSupported, "Scenes are not supported"));
    }

private:
    void applyConfig()
    {
        if (!hasConfig())
            return;
        const Json::Value meta = parseObject(config().adapter.metaJson);
        m_allowUntrusted = meta.get(kAllowUntrustedField, false).asBool();
    }

    // Reads a node's structure and publishes every OnOff-serving endpoint as
    // a device, then subscribes.
    void adoptNode(std::uint64_t nodeId)
    {
        describeAndPublish(nodeId, true);
    }

    void describeAndPublish(std::uint64_t nodeId, bool subscribe = false)
    {
        m_controller.describe(nodeId, [this, subscribe](const phimatter::NodeInfo &info, CHIP_ERROR err) {
            if (err != CHIP_NO_ERROR) {
                char text[96];
                std::snprintf(text, sizeof(text), "node 0x%llx: cannot read its structure: %s",
                              static_cast<unsigned long long>(info.nodeId), phimatter::errorText(err));
                log(phi::LogLevel::Warn, phi::LogCategory::Device, text, {}, "matter.node.describe.failed");
                return;
            }
            publishNode(info);
            if (subscribe)
                m_controller.subscribeOnOff(info.nodeId);
        });
    }

    static std::string hexList(const std::vector<std::uint32_t> &values)
    {
        std::string out;
        for (const std::uint32_t v : values) {
            char text[16];
            std::snprintf(text, sizeof(text), "%s0x%04x", out.empty() ? "" : " ", static_cast<unsigned>(v));
            out += text;
        }
        return out;
    }

    void publishNode(const phimatter::NodeInfo &rawInfo)
    {
        // Vendors pad their strings; the Hama bridge reports " 00176637".
        phimatter::NodeInfo info = rawInfo;
        info.vendor = trimmed(info.vendor);
        info.product = trimmed(info.product);
        info.label = trimmed(info.label);
        info.software = trimmed(info.software);
        for (auto &ep : info.endpoints) {
            ep.label = trimmed(ep.label);
            ep.vendor = trimmed(ep.vendor);
            ep.product = trimmed(ep.product);
        }

        std::size_t onOffEndpoints = 0;
        for (const auto &ep : info.endpoints) {
            if (std::find(ep.serverClusters.begin(), ep.serverClusters.end(), kOnOffClusterId) != ep.serverClusters.end())
                ++onOffEndpoints;
        }

        const std::string nodeName = !info.label.empty() ? info.label : info.product;
        std::size_t published = 0;

        for (const auto &ep : info.endpoints) {
            char text[256];
            std::snprintf(text, sizeof(text), "node 0x%llx endpoint %u: types [%s] servers [%s]%s%s",
                          static_cast<unsigned long long>(info.nodeId), static_cast<unsigned>(ep.endpoint),
                          hexList(ep.deviceTypes).c_str(), hexList(ep.serverClusters).c_str(),
                          ep.label.empty() ? "" : " label ", ep.label.c_str());
            log(phi::LogLevel::Info, phi::LogCategory::Device, text, {}, "matter.node.endpoint");
        }

        // A node with nothing to switch is still a member of the fabric; a
        // bridge without devices is the usual case. Show it as a gateway so
        // that its presence is visible, channels or not.
        if (onOffEndpoints == 0) {
            v1::Device gateway;
            gateway.externalId = deviceExternalId(info.nodeId, 0);
            gateway.deviceClass = v1::DeviceClass::Gateway;
            gateway.manufacturer = info.vendor;
            gateway.model = info.product;
            gateway.firmware = info.software;
            gateway.name = nodeName.empty() ? gateway.externalId : nodeName;
            char nodeText[32];
            std::snprintf(nodeText, sizeof(nodeText), "0x%llx", static_cast<unsigned long long>(info.nodeId));
            gateway.metaJson = std::string("{\"kind\":\"matter\",\"nodeId\":\"") + nodeText + "\",\"endpoint\":0}";
            std::string error;
            if (!sendDeviceUpdated(gateway, {}, &error)) {
                log(phi::LogLevel::Error, phi::LogCategory::Internal, "Failed to publish %1: %2",
                    phi::ScalarList{gateway.externalId, error}, "matter.device.publish.failed");
            } else {
                ++published;
            }
        }
        for (const auto &ep : info.endpoints) {
            if (std::find(ep.serverClusters.begin(), ep.serverClusters.end(), kOnOffClusterId) == ep.serverClusters.end())
                continue;

            v1::Device device;
            device.externalId = deviceExternalId(info.nodeId, ep.endpoint);
            device.deviceClass = deviceClassFor(ep.deviceTypes);
            device.manufacturer = !ep.vendor.empty() ? ep.vendor : info.vendor;
            device.model = !ep.product.empty() ? ep.product : info.product;
            device.firmware = info.software;
            device.flags = v1::DeviceFlag::Wireless;
            if (!ep.label.empty()) {
                device.name = ep.label;
            } else if (onOffEndpoints > 1) {
                device.name = nodeName + " " + std::to_string(ep.endpoint);
            } else {
                device.name = nodeName;
            }
            if (device.name.empty())
                device.name = device.externalId;

            Json::Value meta(Json::objectValue);
            meta["kind"] = "matter";
            char nodeText[32];
            std::snprintf(nodeText, sizeof(nodeText), "0x%llx", static_cast<unsigned long long>(info.nodeId));
            meta["nodeId"] = nodeText;
            meta["endpoint"] = ep.endpoint;
            Json::Value types(Json::arrayValue);
            for (const std::uint32_t type : ep.deviceTypes)
                types.append(type);
            meta["deviceTypes"] = types;
            Json::StreamWriterBuilder builder;
            builder["indentation"] = "";
            device.metaJson = Json::writeString(builder, meta);

            v1::Channel power;
            power.externalId = kOnOffChannel;
            power.name = "Power";
            power.kind = v1::ChannelKind::PowerOnOff;
            power.dataType = v1::ChannelDataType::Bool;
            power.flags = v1::kChannelFlagDefaultWrite;

            v1::ChannelList channels;
            channels.push_back(power);
            std::string error;
            if (!sendDeviceUpdated(device, channels, &error)) {
                log(phi::LogLevel::Error, phi::LogCategory::Internal, "Failed to publish %1: %2",
                    phi::ScalarList{device.externalId, error}, "matter.device.publish.failed");
            } else {
                ++published;
            }
        }

        char text[160];
        std::snprintf(text, sizeof(text), "node 0x%llx (%s / %s): %zu endpoints, %zu devices published",
                      static_cast<unsigned long long>(info.nodeId), info.vendor.c_str(), info.product.c_str(),
                      info.endpoints.size(), published);
        log(phi::LogLevel::Info, phi::LogCategory::Device, text, {}, "matter.node.published");
    }

    static v1::CmdResponse makeResponse(phi::CmdId cmdId, v1::CmdStatus status, std::string error)
    {
        v1::CmdResponse resp;
        resp.id = cmdId;
        resp.status = status;
        resp.error = std::move(error);
        resp.tsMs = nowMs();
        return resp;
    }

    void submit(v1::CmdResponse resp)
    {
        std::string error;
        if (!sendResult(resp, &error))
            log(phi::LogLevel::Error, phi::LogCategory::Internal, "Failed to send command result: %1",
                phi::ScalarList{error}, "matter.result.send.failed");
    }

    void submitAction(v1::ActionResponse resp)
    {
        std::string error;
        if (!sendResult(resp, &error))
            log(phi::LogLevel::Error, phi::LogCategory::Internal, "Failed to send action result: %1",
                phi::ScalarList{error}, "matter.result.send.failed");
    }

    std::string m_stateRoot;
    phimatter::Controller m_controller;
    bool m_started = false;
    bool m_allowUntrusted = false;
};

class MatterFactory final : public phi::AdapterFactory
{
public:
    explicit MatterFactory(std::string stateRoot) : m_stateRoot(std::move(stateRoot)) {}

protected:
    phi::Utf8String pluginType() const override { return kPluginType; }
    phi::Utf8String displayName() const override { return kDisplayName; }
    phi::Utf8String description() const override
    {
        return "Matter controller: commissions Matter devices over Wi-Fi, Ethernet and Thread into a fabric of their own.";
    }
    phi::Utf8String apiVersion() const override { return "1.0.0"; }
    phi::Utf8String iconSvg() const override { return kIconSvg; }
    int timeoutMs() const override { return 10000; }
    // One fabric per tenant for now; a second instance would need its own
    // listen port.
    int maxInstances() const override { return 1; }

    phi::AdapterCapabilities capabilities() const override
    {
        phi::AdapterCapabilities caps;
        caps.required = v1::AdapterRequirement::None;
        caps.optional = v1::AdapterRequirement::None;
        // SupportsDiscovery without a discovery query is what puts a plugin
        // on the discover page as a manual entry; there is nothing to scan
        // for, the fabric is created on the spot.
        caps.flags = v1::AdapterFlag::SupportsDiscovery;

        v1::AdapterActionDescriptor commission;
        commission.id = kCommissionAction;
        commission.label = "Commission device";
        commission.description = "Adds the device behind the pairing code to this fabric.";
        // A dialog with the fields bound to this action by parentActionId;
        // the UI sends their values as the action's params.
        commission.hasForm = true;
        commission.metaJson = R"({"placement":"card","kind":"open_dialog","requiresAck":true})";
        caps.instanceActions.push_back(commission);

        caps.defaultsJson = std::string("{\"name\":") + jsonQuoted(kDisplayName) + ",\"" + kAllowUntrustedField + "\":false}";
        return caps;
    }

    phi::JsonText configSchemaJson() const override
    {
        return R"({
            "factory":{
                "title":"Matter",
                "description":"A Matter controller with a fabric of its own. Nothing to configure here; add an instance and commission devices there.",
                "fields":[]
            },
            "instance":{
                "title":"Matter fabric",
                "description":"Devices join this fabric with their pairing code: the 11-digit manual code or the text behind the QR code (MT:...). The device must already be on the network.",
                "layout":{"gridUnits":24,"gutter":[12,8],"defaults":{"span":{"xs":24,"sm":24,"md":12,"lg":12,"xl":12,"xxl":12},"labelPosition":"top","labelSpan":8,"controlSpan":16,"actionPosition":"inline","actionSpan":6}},
                "fields":[
                    {"key":"pairingCode","type":"String","label":"Pairing code","description":"The code printed on the device or shown by its maker's app (Hue: Settings, Smart home, Matter). Either the 11-digit manual code or the text behind the QR code.","placeholder":"MT:... or 3497-011-2332","flags":["Required","Transient"],"parentActionId":"commission"},
                    {"key":"allowUntrustedAttestation","type":"Boolean","label":"Allow uncertified devices","description":"Continue commissioning when the device's attestation certificate is not signed by a known Matter PAA. Needed for sample apps and development boards.","default":false}
                ]
            }
        })";
    }

    std::unique_ptr<phi::AdapterInstance> createInstance(const phi::ExternalId &externalId) override
    {
        log(phi::LogLevel::Info, phi::LogCategory::Lifecycle, "Create Matter instance %1", phi::ScalarList{externalId},
            "matter.factory.instance.create");
        return std::make_unique<MatterInstance>(m_stateRoot);
    }

private:
    std::string m_stateRoot;
};

} // namespace

int main(int argc, char **argv)
{
    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    const char *envSocketPath = std::getenv("PHI_ADAPTER_SOCKET_PATH");
    const phi::Utf8String socketPath = (argc > 1)
        ? argv[1]
        : (envSocketPath ? envSocketPath : phi::Utf8String("/tmp/phi-adapter-matter-ipc.sock"));

    MatterFactory factory(stateRoot(socketPath));
    phi::SidecarHost host(socketPath, factory);

    phi::SidecarMainOptions options;
    options.installSignalHandlers = false;
    options.keepRunning = []() { return g_running.load(); };
    return phi::runSidecarMain(host, options);
}
