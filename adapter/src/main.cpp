// phi_adapter_matter_ipc: the Matter controller as a phi adapter sidecar.
//
// One instance is one fabric. Devices are commissioned over the network with a
// setup code, every endpoint that serves OnOff becomes a phi device with a
// power channel, and one subscription per node keeps the state current.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <optional>
#include <set>
#include <unordered_map>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <json/json.h>

#include "phi/adapter/sdk/sidecar.h"
#include "phi/adapter/v1/color.h"

#include "controller.h"

namespace phi = phicore::adapter::sdk;
namespace v1 = phicore::adapter::v1;

namespace {

constexpr const char kPluginType[] = "matter";
constexpr const char kDisplayName[] = "Matter";
constexpr const char kCommissionAction[] = "commission";
constexpr const char kPairingCodeField[] = "pairingCode";
constexpr const char kRemoveAction[] = "remove";
constexpr const char kShareAction[] = "share";
constexpr const char kShareDeviceField[] = "shareDevice";
constexpr std::uint16_t kShareWindowSeconds = 300;
constexpr const char kRemoveDeviceField[] = "removeDevice";
constexpr const char kAllowUntrustedField[] = "allowUntrustedAttestation";
constexpr const char kListenPortField[] = "listenPort";
constexpr const char kConnectivityChannel[] = "connectivity";
constexpr const char kColorChannel[] = "color";
constexpr const char kColorTemperatureChannel[] = "colortemp";
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

bool isSensorType(std::uint32_t type);

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
        if (isSensorType(type))
            return v1::DeviceClass::Sensor;
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

// Clusters and attributes the channel model is made of.
namespace cluster {
constexpr std::uint32_t OnOff = 0x0006;
constexpr std::uint32_t LevelControl = 0x0008;
constexpr std::uint32_t PowerSource = 0x002F;
constexpr std::uint32_t BooleanState = 0x0045;
constexpr std::uint32_t IlluminanceMeasurement = 0x0400;
constexpr std::uint32_t TemperatureMeasurement = 0x0402;
constexpr std::uint32_t RelativeHumidityMeasurement = 0x0405;
constexpr std::uint32_t OccupancySensing = 0x0406;
constexpr std::uint32_t ColorControl = 0x0300;
} // namespace cluster
namespace attribute {
constexpr std::uint32_t OnOff = 0x0000;
constexpr std::uint32_t CurrentLevel = 0x0000;
constexpr std::uint32_t BatPercentRemaining = 0x000C;
constexpr std::uint32_t StateValue = 0x0000;
constexpr std::uint32_t MeasuredValue = 0x0000;
constexpr std::uint32_t Occupancy = 0x0000;
constexpr std::uint32_t CurrentHue = 0x0000;
constexpr std::uint32_t CurrentSaturation = 0x0001;
constexpr std::uint32_t CurrentX = 0x0003;
constexpr std::uint32_t CurrentY = 0x0004;
constexpr std::uint32_t ColorTemperatureMireds = 0x0007;
constexpr std::uint32_t ColorMode = 0x0008;
} // namespace attribute

// Color Control capabilities and modes.
constexpr std::uint16_t kColorCapHueSaturation = 0x0001;
constexpr std::uint16_t kColorCapXy = 0x0008;
constexpr std::uint16_t kColorCapTemperature = 0x0010;
constexpr double kColorModeXy = 1.0;
constexpr double kColorModeTemperature = 2.0;
constexpr std::uint16_t kDefaultMinMireds = 153;
constexpr std::uint16_t kDefaultMaxMireds = 500;

constexpr std::uint32_t kAggregatorType = 0x000E;
constexpr std::uint32_t kOccupancySensorType = 0x0107;
constexpr std::uint32_t kContactSensorType = 0x0015;
constexpr std::uint32_t kTemperatureSensorType = 0x0302;
constexpr std::uint32_t kHumiditySensorType = 0x0307;
constexpr std::uint32_t kLightSensorType = 0x0106;

// One phi channel: which attribute feeds it and how it is described.
struct ChannelSpec {
    const char *id;
    std::uint32_t cluster;
    std::uint32_t attribute;
    v1::ChannelKind kind;
    v1::ChannelDataType dataType;
    v1::ChannelFlags flags;
    const char *unit;
    double minValue;
    double maxValue;
    double stepValue;
};

bool hasCluster(const phimatter::EndpointInfo &ep, std::uint32_t cluster)
{
    return std::find(ep.serverClusters.begin(), ep.serverClusters.end(), cluster) != ep.serverClusters.end();
}

bool hasDeviceType(const phimatter::EndpointInfo &ep, std::uint32_t type)
{
    return std::find(ep.deviceTypes.begin(), ep.deviceTypes.end(), type) != ep.deviceTypes.end();
}

std::vector<ChannelSpec> channelsFor(const phimatter::EndpointInfo &ep)
{
    using v1::ChannelDataType;
    using v1::ChannelKind;
    std::vector<ChannelSpec> out;
    if (hasCluster(ep, cluster::OnOff))
        out.push_back({"onoff", cluster::OnOff, attribute::OnOff, ChannelKind::PowerOnOff, ChannelDataType::Bool,
                       v1::kChannelFlagDefaultWrite, "", 0, 0, 0});
    if (hasCluster(ep, cluster::LevelControl))
        out.push_back({"brightness", cluster::LevelControl, attribute::CurrentLevel, ChannelKind::Brightness,
                       ChannelDataType::Float, v1::kChannelFlagDefaultWrite, "%", 0, 100, 1});
    if (hasCluster(ep, cluster::ColorControl)) {
        // The capabilities bitmap says what the light can do; a device that
        // did not answer it is judged by its device type.
        std::uint16_t caps = ep.colorCapabilities;
        if (caps == 0) {
            if (hasDeviceType(ep, ExtendedColorLight))
                caps = kColorCapHueSaturation | kColorCapTemperature;
            else if (hasDeviceType(ep, ColorTemperatureLight))
                caps = kColorCapTemperature;
        }
        if (caps & kColorCapTemperature) {
            const double minMireds = ep.colorTempMinMireds > 0 ? ep.colorTempMinMireds : kDefaultMinMireds;
            const double maxMireds = ep.colorTempMaxMireds > 0 ? ep.colorTempMaxMireds : kDefaultMaxMireds;
            out.push_back({kColorTemperatureChannel, cluster::ColorControl, attribute::ColorTemperatureMireds,
                           ChannelKind::ColorTemperature, ChannelDataType::Int, v1::kChannelFlagDefaultWrite, "mired",
                           minMireds, maxMireds, 1});
        }
        if (caps & (kColorCapHueSaturation | kColorCapXy)) {
            // Fed from hue and saturation (or x and y); the attribute here
            // is only the one that names the channel.
            out.push_back({kColorChannel, cluster::ColorControl, attribute::CurrentHue, ChannelKind::ColorRGB,
                           ChannelDataType::Color, v1::kChannelFlagDefaultWrite, "", 0, 0, 0});
        }
    }
    if (hasCluster(ep, cluster::OccupancySensing))
        out.push_back({"motion", cluster::OccupancySensing, attribute::Occupancy, ChannelKind::Motion, ChannelDataType::Bool,
                       v1::kChannelFlagDefaultRead, "", 0, 0, 0});
    if (hasCluster(ep, cluster::BooleanState)) {
        // Boolean State is what a contact sensor reports. Some bridges use it
        // for occupancy sensors too, and then the device type says so.
        const bool occupancy = hasDeviceType(ep, kOccupancySensorType) && !hasCluster(ep, cluster::OccupancySensing);
        out.push_back({occupancy ? "motion" : "contact", cluster::BooleanState, attribute::StateValue,
                       occupancy ? ChannelKind::Motion : ChannelKind::Contact, ChannelDataType::Bool,
                       v1::kChannelFlagDefaultRead, "", 0, 0, 0});
    }
    if (hasCluster(ep, cluster::TemperatureMeasurement))
        out.push_back({"temperature", cluster::TemperatureMeasurement, attribute::MeasuredValue, ChannelKind::Temperature,
                       ChannelDataType::Float, v1::kChannelFlagDefaultRead, "C", -50, 150, 0.01});
    if (hasCluster(ep, cluster::RelativeHumidityMeasurement))
        out.push_back({"humidity", cluster::RelativeHumidityMeasurement, attribute::MeasuredValue, ChannelKind::Humidity,
                       ChannelDataType::Float, v1::kChannelFlagDefaultRead, "%", 0, 100, 0.01});
    if (hasCluster(ep, cluster::IlluminanceMeasurement))
        out.push_back({"illuminance", cluster::IlluminanceMeasurement, attribute::MeasuredValue, ChannelKind::Illuminance,
                       ChannelDataType::Float, v1::kChannelFlagDefaultRead, "lx", 0, 100000, 1});
    // Power Source on the root endpoint describes the mains; on a device
    // endpoint it is the battery.
    if (ep.endpoint != 0 && hasCluster(ep, cluster::PowerSource))
        out.push_back({"battery", cluster::PowerSource, attribute::BatPercentRemaining, ChannelKind::Battery,
                       ChannelDataType::Int, v1::kChannelFlagDefaultRead, "%", 0, 100, 1});
    return out;
}

// The reported attribute as the channel's value; monostate when the device
// reported null.
v1::ScalarValue channelValue(const ChannelSpec &spec, const phimatter::AttributeValue &value)
{
    if (value.isNull)
        return v1::ScalarValue{};
    switch (spec.kind) {
    case v1::ChannelKind::PowerOnOff:
    case v1::ChannelKind::Motion:
    case v1::ChannelKind::Contact:
        return v1::ScalarValue(value.boolean);
    case v1::ChannelKind::Brightness:
        return v1::ScalarValue(std::round(value.number / 254.0 * 1000.0) / 10.0);
    case v1::ChannelKind::Battery:
        // Half-percent units.
        return v1::ScalarValue(static_cast<std::int64_t>(std::lround(value.number / 2.0)));
    case v1::ChannelKind::ColorTemperature:
        return v1::ScalarValue(static_cast<std::int64_t>(std::lround(value.number)));
    case v1::ChannelKind::Temperature:
    case v1::ChannelKind::Humidity:
        return v1::ScalarValue(value.number / 100.0);
    case v1::ChannelKind::Illuminance:
        // 10000 * log10(lux) + 1, 0 meaning "too low to measure".
        return v1::ScalarValue(value.number <= 0 ? 0.0 : std::pow(10.0, (value.number - 1.0) / 10000.0));
    default:
        return v1::ScalarValue(value.number);
    }
}

bool isSensorType(std::uint32_t type)
{
    return type == kOccupancySensorType || type == kContactSensorType || type == kTemperatureSensorType
        || type == kHumiditySensorType || type == kLightSensorType;
}

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

// A node as a person names it: "0x1", "1", or a device id "n1-e3".
bool parseNodeReference(std::string text, std::uint64_t *nodeId)
{
    text = trimmed(std::move(text));
    if (text.empty())
        return false;
    std::uint16_t endpoint = 0;
    if (parseDeviceExternalId(text, nodeId, &endpoint))
        return true;
    char *end = nullptr;
    const unsigned long long value = std::strtoull(text.c_str(), &end, 0);
    if (end == text.c_str() || *end != '\0' || value == 0)
        return false;
    *nodeId = value;
    return true;
}

std::string nodeText(std::uint64_t nodeId)
{
    char text[32];
    std::snprintf(text, sizeof(text), "0x%llx", static_cast<unsigned long long>(nodeId));
    return text;
}

// "#rrggbb" or "rrggbb".
bool parseHexColor(std::string text, double *r, double *g, double *b)
{
    text = trimmed(std::move(text));
    if (!text.empty() && text[0] == '#')
        text.erase(0, 1);
    if (text.size() != 6)
        return false;
    unsigned value = 0;
    char *end = nullptr;
    value = static_cast<unsigned>(std::strtoul(text.c_str(), &end, 16));
    if (end == text.c_str() || *end != '\0')
        return false;
    *r = ((value >> 16) & 0xFF) / 255.0;
    *g = ((value >> 8) & 0xFF) / 255.0;
    *b = (value & 0xFF) / 255.0;
    return true;
}

// The color a channel write carries: a hex string, {"hex":...} or {"r","g","b"}
// in 0..1 or 0..255, the same shapes the other adapters accept.
bool colorFromRequest(const phi::ChannelInvokeRequest &request, double *r, double *g, double *b)
{
    if (request.hasScalarValue) {
        if (const auto *text = std::get_if<std::string>(&request.value))
            return parseHexColor(*text, r, g, b);
    }
    if (request.valueJson.empty())
        return false;
    const Json::Value obj = parseObject(request.valueJson);
    if (obj.isMember("hex"))
        return parseHexColor(obj["hex"].asString(), r, g, b);
    if (!obj.isMember("r") || !obj.isMember("g") || !obj.isMember("b"))
        return false;
    double red = obj["r"].asDouble();
    double green = obj["g"].asDouble();
    double blue = obj["b"].asDouble();
    if (red > 1.0 || green > 1.0 || blue > 1.0) {
        red /= 255.0;
        green /= 255.0;
        blue /= 255.0;
    }
    *r = v1::clamp01(red);
    *g = v1::clamp01(green);
    *b = v1::clamp01(blue);
    return true;
}

// What a color light last reported, enough to turn it into sRGB.
struct ColorState {
    double hue = 0;        // 0..254
    double saturation = 0; // 0..254
    double x = 0;          // 0..65535
    double y = 0;
    double mode = 0;
    bool haveHue = false;
    bool haveSaturation = false;
    bool haveX = false;
    bool haveY = false;

    std::optional<v1::Color> color() const
    {
        if (mode == kColorModeTemperature)
            return std::nullopt;
        if (mode == kColorModeXy && haveX && haveY)
            return v1::colorFromXy(x / 65535.0, y / 65535.0, 1.0);
        if (haveHue && haveSaturation)
            return v1::hsvToColor(hue / 254.0 * 360.0, saturation / 254.0, 1.0);
        return std::nullopt;
    }
};

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
        options.listenPort = m_listenPort;

        phimatter::Callbacks callbacks;
        callbacks.log = [this](phimatter::LogLevel level, const std::string &message) {
            log(toSdkLevel(level), phi::LogCategory::Protocol, message, {}, "matter.chip");
        };
        callbacks.attribute = [this](std::uint64_t nodeId, std::uint16_t endpoint, std::uint32_t clusterId,
                                     std::uint32_t attributeId, const phimatter::AttributeValue &value) {
            const std::string device = deviceExternalId(nodeId, endpoint);
            if (clusterId == cluster::ColorControl && attributeId != attribute::ColorTemperatureMireds) {
                onColorAttribute(device, attributeId, value);
                return;
            }
            const std::optional<ChannelSpec> spec = findSpec(device, clusterId, attributeId);
            if (!spec)
                return;
            const v1::ScalarValue scalar = channelValue(*spec, value);
            if (std::holds_alternative<std::monostate>(scalar))
                return;
            sendChannelStateUpdated(device, spec->id, scalar, nowMs());
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
            const auto status = reachable ? v1::ConnectivityStatus::Connected : v1::ConnectivityStatus::Disconnected;
            for (const std::string &device : devicesOf(nodeId))
                sendChannelStateUpdated(device, kConnectivityChannel, v1::ScalarValue(static_cast<std::int64_t>(status)), nowMs());
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
        if (!parseDeviceExternalId(request.deviceExternalId, &nodeId, &endpoint)) {
            submit(makeResponse(request.cmdId, v1::CmdStatus::NotSupported, "Unknown Matter device"));
            return;
        }
        if (!m_started) {
            submit(makeResponse(request.cmdId, v1::CmdStatus::TemporarilyOffline, "Matter stack is not running"));
            return;
        }
        const phi::CmdId cmdId = request.cmdId;
        const std::string device = request.deviceExternalId;
        const std::string channel = request.channelExternalId;

        auto finish = [this, cmdId, device, channel](CHIP_ERROR err, v1::ScalarValue applied) {
            if (err == CHIP_NO_ERROR) {
                v1::CmdResponse resp = makeResponse(cmdId, v1::CmdStatus::Success, {});
                resp.finalValue = applied;
                submit(std::move(resp));
                sendChannelStateUpdated(device, channel, applied, nowMs());
            } else {
                submit(makeResponse(cmdId, v1::CmdStatus::Failure, phimatter::errorText(err)));
            }
        };

        if (channel == "onoff") {
            if (!request.hasScalarValue || !std::holds_alternative<bool>(request.value)) {
                submit(makeResponse(cmdId, v1::CmdStatus::InvalidArgument, "OnOff wants a boolean"));
                return;
            }
            const bool on = std::get<bool>(request.value);
            m_controller.setOnOff(nodeId, endpoint, on, [finish, on](CHIP_ERROR err) { finish(err, v1::ScalarValue(on)); });
            return;
        }
        if (channel == "brightness") {
            double percent = 0.0;
            if (request.hasScalarValue && std::holds_alternative<double>(request.value))
                percent = std::get<double>(request.value);
            else if (request.hasScalarValue && std::holds_alternative<std::int64_t>(request.value))
                percent = static_cast<double>(std::get<std::int64_t>(request.value));
            else {
                submit(makeResponse(cmdId, v1::CmdStatus::InvalidArgument, "Brightness wants a number 0..100"));
                return;
            }
            percent = std::min(100.0, std::max(0.0, percent));
            const auto level = static_cast<std::uint8_t>(std::lround(percent / 100.0 * 254.0));
            m_controller.setLevel(nodeId, endpoint, level, [finish, percent](CHIP_ERROR err) {
                finish(err, v1::ScalarValue(percent));
            });
            return;
        }
        if (channel == kColorTemperatureChannel) {
            double mireds = 0.0;
            if (request.hasScalarValue && std::holds_alternative<double>(request.value))
                mireds = std::get<double>(request.value);
            else if (request.hasScalarValue && std::holds_alternative<std::int64_t>(request.value))
                mireds = static_cast<double>(std::get<std::int64_t>(request.value));
            else {
                submit(makeResponse(cmdId, v1::CmdStatus::InvalidArgument, "Color temperature wants mireds"));
                return;
            }
            const std::optional<ChannelSpec> spec = findSpec(device, cluster::ColorControl, attribute::ColorTemperatureMireds);
            const double lo = spec ? spec->minValue : kDefaultMinMireds;
            const double hi = spec ? spec->maxValue : kDefaultMaxMireds;
            mireds = std::min(hi, std::max(lo, mireds));
            const auto value = static_cast<std::uint16_t>(std::lround(mireds));
            m_controller.setColorTemperature(nodeId, endpoint, value, [finish, value](CHIP_ERROR err) {
                finish(err, v1::ScalarValue(static_cast<std::int64_t>(value)));
            });
            return;
        }
        if (channel == kColorChannel) {
            double r = 0, g = 0, b = 0;
            if (!colorFromRequest(request, &r, &g, &b)) {
                submit(makeResponse(cmdId, v1::CmdStatus::InvalidArgument, "Color wants #rrggbb or {r,g,b}"));
                return;
            }
            const v1::Hsv hsv = v1::colorToHsv(v1::makeColor(r, g, b));
            const auto hue = static_cast<std::uint8_t>(std::lround(hsv.hDeg / 360.0 * 254.0));
            const auto saturation = static_cast<std::uint8_t>(std::lround(hsv.s * 254.0));
            // Brightness is its own channel; the color keeps full value.
            const v1::Color shown = v1::hsvToColor(hsv.hDeg, hsv.s, 1.0);
            m_controller.setHueSaturation(nodeId, endpoint, hue, saturation, [this, cmdId, device, channel, shown](CHIP_ERROR err) {
                if (err != CHIP_NO_ERROR) {
                    submit(makeResponse(cmdId, v1::CmdStatus::Failure, phimatter::errorText(err)));
                    return;
                }
                submit(makeResponse(cmdId, v1::CmdStatus::Success, {}));
                sendChannelColorStateUpdated(device, channel, shown.r, shown.g, shown.b, nowMs());
            });
            return;
        }
        submit(makeResponse(cmdId, v1::CmdStatus::NotSupported, "Channel is read-only"));
    }

    void onAdapterActionInvoke(const phi::AdapterActionInvokeRequest &request) override
    {
        v1::ActionResponse resp;
        resp.id = request.cmdId;
        resp.tsMs = nowMs();

        if (request.actionId == kRemoveAction) {
            removeAction(request, std::move(resp));
            return;
        }
        if (request.actionId == kShareAction) {
            shareAction(request, std::move(resp));
            return;
        }
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
        const int port = meta.get(kListenPortField, 0).asInt();
        m_listenPort = (port > 0 && port < 65536) ? static_cast<std::uint16_t>(port) : 0;
    }

    // Resolves the node a form names, answering the request when it cannot.
    bool nodeFromForm(const phi::AdapterActionInvokeRequest &request, const char *field, v1::ActionResponse &resp,
                      std::uint64_t *nodeId)
    {
        const Json::Value params = parseObject(request.paramsJson);
        if (!parseNodeReference(params.get(field, "").asString(), nodeId)) {
            resp.status = v1::CmdStatus::InvalidArgument;
            resp.error = "Name the node: its id (0x1) or one of its devices (n1-e3)";
            submitAction(std::move(resp));
            return false;
        }
        if (!m_started) {
            resp.status = v1::CmdStatus::TemporarilyOffline;
            resp.error = "Matter stack is not running";
            submitAction(std::move(resp));
            return false;
        }
        const auto known = m_controller.nodes();
        if (std::find(known.begin(), known.end(), *nodeId) == known.end()) {
            resp.status = v1::CmdStatus::InvalidArgument;
            resp.error = "Node " + nodeText(*nodeId) + " is not in this fabric";
            submitAction(std::move(resp));
            return false;
        }
        return true;
    }

    void shareAction(const phi::AdapterActionInvokeRequest &request, v1::ActionResponse resp)
    {
        std::uint64_t nodeId = 0;
        if (!nodeFromForm(request, kShareDeviceField, resp, &nodeId))
            return;
        const phi::CmdId cmdId = request.cmdId;
        m_controller.share(nodeId, kShareWindowSeconds, [this, cmdId, nodeId](const std::string &manual, const std::string &qr, CHIP_ERROR err) {
            v1::ActionResponse done;
            done.id = cmdId;
            done.tsMs = nowMs();
            if (err != CHIP_NO_ERROR) {
                done.status = v1::CmdStatus::Failure;
                done.error = "Could not open the commissioning window on node " + nodeText(nodeId) + ": " + phimatter::errorText(err);
                submitAction(std::move(done));
                return;
            }
            done.status = v1::CmdStatus::Success;
            done.resultType = v1::ActionResultType::String;
            std::string text = "Node " + nodeText(nodeId) + " is open for " + std::to_string(kShareWindowSeconds / 60)
                + " minutes. Pairing code for the other app: " + manual;
            if (!qr.empty())
                text += " (QR payload " + qr + ")";
            done.resultValue = v1::ScalarValue(text);
            done.formValuesJson = std::string("{\"") + kShareDeviceField + "\":\"\"}";
            submitAction(std::move(done));
        });
    }

    void removeAction(const phi::AdapterActionInvokeRequest &request, v1::ActionResponse resp)
    {
        std::uint64_t nodeId = 0;
        if (!nodeFromForm(request, kRemoveDeviceField, resp, &nodeId))
            return;
        const phi::CmdId cmdId = request.cmdId;
        m_controller.remove(nodeId, [this, cmdId, nodeId](CHIP_ERROR err) {
            for (const std::string &device : devicesOf(nodeId)) {
                std::string error;
                if (!sendDeviceRemoved(device, &error)) {
                    log(phi::LogLevel::Error, phi::LogCategory::Internal, "Failed to remove %1: %2",
                        phi::ScalarList{device, error}, "matter.device.remove.failed");
                }
            }
            dropNode(nodeId);

            v1::ActionResponse done;
            done.id = cmdId;
            done.tsMs = nowMs();
            done.status = v1::CmdStatus::Success;
            done.resultType = v1::ActionResultType::String;
            if (err == CHIP_NO_ERROR) {
                done.resultValue = v1::ScalarValue("Removed node " + nodeText(nodeId));
            } else {
                // Forgotten here regardless; the device keeps a fabric it
                // cannot use until somebody resets it.
                done.resultValue = v1::ScalarValue("Node " + nodeText(nodeId) + " forgotten; the device did not let go of the fabric ("
                                                   + phimatter::errorText(err) + "), a factory reset clears it");
            }
            done.formValuesJson = std::string("{\"") + kRemoveDeviceField + "\":\"\"}";
            submitAction(std::move(done));
        });
    }

    // Color Control reports arrive one attribute at a time; the channel wants
    // all of them, so they are kept per device and the color is sent whenever
    // one of them moves.
    void onColorAttribute(const std::string &device, std::uint32_t attributeId, const phimatter::AttributeValue &value)
    {
        if (value.isNull)
            return;
        std::optional<v1::Color> color;
        {
            std::lock_guard<std::mutex> lock(m_specsMutex);
            const auto specs = m_specs.find(device);
            if (specs == m_specs.end())
                return;
            const bool hasColor = std::any_of(specs->second.begin(), specs->second.end(),
                                              [](const ChannelSpec &spec) { return spec.kind == v1::ChannelKind::ColorRGB; });
            if (!hasColor)
                return;
            ColorState &state = m_colors[device];
            switch (attributeId) {
            case attribute::CurrentHue: state.hue = value.number; state.haveHue = true; break;
            case attribute::CurrentSaturation: state.saturation = value.number; state.haveSaturation = true; break;
            case attribute::CurrentX: state.x = value.number; state.haveX = true; break;
            case attribute::CurrentY: state.y = value.number; state.haveY = true; break;
            case attribute::ColorMode: state.mode = value.number; break;
            default: return;
            }
            color = state.color();
        }
        if (color)
            sendChannelColorStateUpdated(device, kColorChannel, color->r, color->g, color->b, nowMs());
    }

    std::vector<std::string> devicesOf(std::uint64_t nodeId) const
    {
        std::lock_guard<std::mutex> lock(m_specsMutex);
        const auto it = m_devicesByNode.find(nodeId);
        if (it == m_devicesByNode.end())
            return {};
        return std::vector<std::string>(it->second.begin(), it->second.end());
    }

    void rememberDevice(std::uint64_t nodeId, const std::string &device)
    {
        std::lock_guard<std::mutex> lock(m_specsMutex);
        m_devicesByNode[nodeId].insert(device);
    }

    void dropNode(std::uint64_t nodeId)
    {
        std::lock_guard<std::mutex> lock(m_specsMutex);
        const auto it = m_devicesByNode.find(nodeId);
        if (it == m_devicesByNode.end())
            return;
        for (const std::string &device : it->second) {
            m_specs.erase(device);
            m_colors.erase(device);
        }
        m_devicesByNode.erase(it);
    }

    // Every device carries the node's reachability, the way the Zigbee
    // adapter does it: the UI reads this channel for its offline mark.
    static v1::Channel connectivityChannel()
    {
        v1::Channel channel;
        channel.externalId = kConnectivityChannel;
        channel.name = "Connectivity";
        channel.kind = v1::ChannelKind::ConnectivityStatus;
        channel.dataType = v1::ChannelDataType::Enum;
        channel.flags = v1::ChannelFlag::Readable | v1::ChannelFlag::Reportable | v1::ChannelFlag::Retained;
        return channel;
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
                m_controller.subscribe(info.nodeId);
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

        std::size_t publishable = 0;
        for (const auto &ep : info.endpoints) {
            if (!channelsFor(ep).empty())
                ++publishable;
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

        // A bridge is shown as a gateway beside the devices it carries, and a
        // node with nothing to report is shown as one too: membership in the
        // fabric stays visible, channels or not.
        const bool aggregator = std::any_of(info.endpoints.begin(), info.endpoints.end(), [](const auto &ep) {
            return hasDeviceType(ep, kAggregatorType);
        });
        if (publishable == 0 || aggregator) {
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
            rememberDevice(info.nodeId, gateway.externalId);
            std::string error;
            if (!sendDeviceUpdated(gateway, {connectivityChannel()}, &error)) {
                log(phi::LogLevel::Error, phi::LogCategory::Internal, "Failed to publish %1: %2",
                    phi::ScalarList{gateway.externalId, error}, "matter.device.publish.failed");
            } else {
                ++published;
            }
        }

        for (const auto &ep : info.endpoints) {
            const std::vector<ChannelSpec> specs = channelsFor(ep);
            if (specs.empty())
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
            } else if (publishable > 1) {
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

            v1::ChannelList channels;
            for (const ChannelSpec &spec : specs) {
                v1::Channel channel;
                channel.externalId = spec.id;
                channel.name = channelName(spec);
                channel.kind = spec.kind;
                channel.dataType = spec.dataType;
                channel.flags = spec.flags;
                channel.unit = spec.unit;
                channel.minValue = spec.minValue;
                channel.maxValue = spec.maxValue;
                channel.stepValue = spec.stepValue;
                channels.push_back(channel);
                if (spec.kind == v1::ChannelKind::Battery)
                    device.flags = device.flags | v1::DeviceFlag::Battery;
            }
            channels.push_back(connectivityChannel());
            {
                std::lock_guard<std::mutex> lock(m_specsMutex);
                m_specs[device.externalId] = specs;
                m_devicesByNode[info.nodeId].insert(device.externalId);
            }

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

    static const char *channelName(const ChannelSpec &spec)
    {
        switch (spec.kind) {
        case v1::ChannelKind::PowerOnOff: return "Power";
        case v1::ChannelKind::Brightness: return "Brightness";
        case v1::ChannelKind::Motion: return "Motion";
        case v1::ChannelKind::Contact: return "Contact";
        case v1::ChannelKind::Temperature: return "Temperature";
        case v1::ChannelKind::Humidity: return "Humidity";
        case v1::ChannelKind::Illuminance: return "Illuminance";
        case v1::ChannelKind::Battery: return "Battery";
        case v1::ChannelKind::ColorTemperature: return "Color temperature";
        case v1::ChannelKind::ColorRGB: return "Color";
        default: return spec.id;
        }
    }

    // A copy, because the map may be rewritten on the host thread meanwhile.
    std::optional<ChannelSpec> findSpec(const std::string &device, std::uint32_t clusterId, std::uint32_t attributeId) const
    {
        std::lock_guard<std::mutex> lock(m_specsMutex);
        const auto it = m_specs.find(device);
        if (it == m_specs.end())
            return std::nullopt;
        for (const ChannelSpec &spec : it->second) {
            if (spec.cluster == clusterId && spec.attribute == attributeId)
                return spec;
        }
        return std::nullopt;
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
    // Channels per published device, by device external id. Written on the
    // host thread in publishNode, read on the Matter thread by the attribute
    // callback; both under the lock.
    mutable std::mutex m_specsMutex;
    std::unordered_map<std::string, std::vector<ChannelSpec>> m_specs;
    std::unordered_map<std::string, ColorState> m_colors;
    std::map<std::uint64_t, std::set<std::string>> m_devicesByNode;
    std::uint16_t m_listenPort = 0;
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

        v1::AdapterActionDescriptor share;
        share.id = kShareAction;
        share.label = "Share with another app";
        share.description = "Opens the device for Apple Home, Google Home or the maker's app for five minutes and shows the code to enter there.";
        share.hasForm = true;
        share.metaJson = R"({"placement":"card","kind":"open_dialog","requiresAck":true})";
        caps.instanceActions.push_back(share);

        v1::AdapterActionDescriptor remove;
        remove.id = kRemoveAction;
        remove.label = "Remove device";
        remove.description = "Takes this fabric off the device and forgets it here.";
        remove.hasForm = true;
        remove.danger = true;
        remove.metaJson = R"({"placement":"card","kind":"open_dialog","requiresAck":true})";
        caps.instanceActions.push_back(remove);

        caps.defaultsJson = std::string("{\"name\":") + jsonQuoted(kDisplayName) + ",\"" + kAllowUntrustedField + "\":false,\"" + kListenPortField + "\":5540}";
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
                    {"key":"shareDevice","type":"String","label":"Device to share","description":"The node id shown in a device's details (0x1), or the id of one of its devices (n1-e3). The other app then adds the device with the code this shows; it stays in this fabric too.","placeholder":"0x1 or n1-e3","flags":["Required","Transient"],"parentActionId":"share"},
                    {"key":"removeDevice","type":"String","label":"Device to remove","description":"The node id shown in a device's details (0x1), or the id of one of its devices (n1-e3). A bridge goes with everything behind it.","placeholder":"0x1 or n1-e3","flags":["Required","Transient"],"parentActionId":"remove"},
                    {"key":"allowUntrustedAttestation","type":"Boolean","label":"Allow uncertified devices","description":"Continue commissioning when the device's attestation certificate is not signed by a known Matter PAA. Needed for sample apps and development boards.","default":false},
                    {"key":"listenPort","type":"Int","label":"UDP port","description":"The port this controller answers on. Matter's default is 5540; a second core on the same host needs another one. Takes effect when the instance restarts.","default":5540,"min":1024,"max":65535}
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
