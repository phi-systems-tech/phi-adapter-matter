#include "controller.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>

#include <app-common/zap-generated/cluster-objects.h>
#include <app-common/zap-generated/ids/Attributes.h>
#include <app-common/zap-generated/ids/Clusters.h>
#include <app/AttributePathParams.h>
#include <app/InteractionModelEngine.h>
#include <app/ReadClient.h>
#include <app/ReadPrepareParams.h>
#include <app/data-model/Decode.h>
#include <controller/CHIPDeviceController.h>
#include <controller/CHIPDeviceControllerFactory.h>
#include <controller/CommissioningDelegate.h>
#include <controller/DevicePairingDelegate.h>
#include <controller/ExampleOperationalCredentialsIssuer.h>
#include <controller/ExamplePersistentStorage.h>
#include <controller/InvokeInteraction.h>
#include <credentials/DeviceAttestationCredsProvider.h>
#include <credentials/GroupDataProvider.h>
#include <credentials/GroupDataProviderImpl.h>
#include <credentials/PersistentStorageOpCertStore.h>
#include <credentials/attestation_verifier/DefaultDeviceAttestationVerifier.h>
#include <credentials/attestation_verifier/DeviceAttestationDelegate.h>
#include <credentials/attestation_verifier/FileAttestationTrustStore.h>
#include <credentials/examples/DeviceAttestationCredsExample.h>
#include <crypto/CHIPCryptoPAL.h>
#include <crypto/PersistentStorageOperationalKeystore.h>
#include <crypto/RawKeySessionKeystore.h>
#include <data-model-providers/codegen/Instance.h>
#include <json/json.h>
#include <lib/core/CASEAuthTag.h>
#include <lib/core/CHIPVendorIdentifiers.hpp>
#include <lib/core/ErrorStr.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/logging/CHIPLogging.h>
#include <platform/CHIPDeviceLayer.h>
#include <platform/PlatformManager.h>

namespace phimatter {

using namespace chip;
using namespace chip::app;
using namespace chip::Controller;

namespace {

constexpr FabricId kFabricId = 1;
constexpr const char *kRegistryFile = "nodes.json";
constexpr std::uint16_t kSubscribeMinIntervalSeconds = 0;
constexpr std::uint16_t kSubscribeMaxIntervalSeconds = 300;

std::string toHex(const std::uint8_t *data, std::size_t size)
{
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(kDigits[data[i] >> 4]);
        out.push_back(kDigits[data[i] & 0x0f]);
    }
    return out;
}

bool fromHex(const std::string &text, std::uint8_t *out, std::size_t size)
{
    if (text.size() != size * 2)
        return false;
    for (std::size_t i = 0; i < size; ++i) {
        unsigned value = 0;
        if (std::sscanf(text.c_str() + i * 2, "%2x", &value) != 1)
            return false;
        out[i] = static_cast<std::uint8_t>(value);
    }
    return true;
}

std::string spanToString(CharSpan span)
{
    return std::string(span.data(), span.size());
}

// Runs a std::function handed to PlatformMgr().ScheduleWork() as an intptr.
void runPosted(intptr_t arg)
{
    auto *task = reinterpret_cast<std::function<void()> *>(arg);
    (*task)();
    delete task;
}

} // namespace

const char *errorText(CHIP_ERROR err)
{
    return ErrorStr(err);
}

// ---------------------------------------------------------------------------

struct Controller::Impl : public DevicePairingDelegate, public Credentials::DeviceAttestationDelegate
{
    Options options;
    Callbacks callbacks;
    std::atomic<bool> allowUntrustedAttestation{false};
    std::atomic<bool> loopRunning{false};

    // The stack.
    PersistentStorage storage;
    PersistentStorageOperationalKeystore operationalKeystore;
    Credentials::PersistentStorageOpCertStore opCertStore;
    Crypto::RawKeySessionKeystore sessionKeystore;
    Credentials::GroupDataProviderImpl groupDataProvider;
    ExampleOperationalCredentialsIssuer opCredsIssuer;
    std::unique_ptr<Credentials::FileAttestationTrustStore> fileTrustStore;
    const Credentials::AttestationTrustStore *trustStore = nullptr;
    Credentials::DeviceAttestationVerifier *dacVerifier = nullptr;
    std::unique_ptr<DeviceCommissioner> commissioner;
    std::uint8_t noc[kMaxCHIPDERCertLength];
    std::uint8_t icac[kMaxCHIPDERCertLength];
    std::uint8_t rcac[kMaxCHIPDERCertLength];

    // The registry: what this fabric knows about, independent of the SDK's
    // own storage so that a person can read it.
    struct NodeRecord {
        std::uint64_t nodeId = 0;
        std::string name;
    };
    mutable std::mutex registryMutex;
    std::map<std::uint64_t, NodeRecord> registry;
    std::uint64_t nextNodeId = 1;
    std::uint8_t ipk[Crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES];

    // Commissioning in flight. Matter thread only.
    struct Commissioning {
        std::uint64_t nodeId = 0;
        std::function<void(std::uint64_t, CHIP_ERROR)> done;
        bool finished = false;
    };
    std::unique_ptr<Commissioning> commissioning;
    CommissioningParameters commissioningParams;

    // ---- logging ------------------------------------------------------

    void log(LogLevel level, const std::string &message)
    {
        if (callbacks.log)
            callbacks.log(level, message);
    }

    static Impl *s_logTarget;

    static void logRedirect(const char *module, std::uint8_t category, const char *msg, va_list args)
    {
        Impl *self = s_logTarget;
        if (self == nullptr || !self->callbacks.log)
            return;
        char buffer[512];
        std::vsnprintf(buffer, sizeof(buffer), msg, args);
        LogLevel level = LogLevel::Trace;
        switch (category) {
        case Logging::kLogCategory_Error: level = LogLevel::Warn; break;
        case Logging::kLogCategory_Progress: level = LogLevel::Debug; break;
        default: level = LogLevel::Trace; break;
        }
        std::string text = "[";
        text += module ? module : "CHIP";
        text += "] ";
        text += buffer;
        self->callbacks.log(level, text);
    }

    // ---- registry -----------------------------------------------------

    std::filesystem::path registryPath() const
    {
        return std::filesystem::path(options.stateDir) / kRegistryFile;
    }

    bool loadRegistry(std::string *error)
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        registry.clear();
        nextNodeId = 1;
        bool haveIpk = false;

        std::ifstream in(registryPath());
        if (in) {
            Json::Value root;
            Json::CharReaderBuilder builder;
            std::string parseError;
            if (!Json::parseFromStream(builder, in, &root, &parseError)) {
                if (error)
                    *error = "registry " + registryPath().string() + ": " + parseError;
                return false;
            }
            if (root.isMember("ipk") && fromHex(root["ipk"].asString(), ipk, sizeof(ipk)))
                haveIpk = true;
            if (root.isMember("nextNodeId"))
                nextNodeId = root["nextNodeId"].asUInt64();
            for (const Json::Value &node : root["nodes"]) {
                NodeRecord record;
                record.nodeId = node["nodeId"].asUInt64();
                record.name = node["name"].asString();
                if (record.nodeId != 0)
                    registry[record.nodeId] = record;
                if (record.nodeId >= nextNodeId)
                    nextNodeId = record.nodeId + 1;
            }
        }

        if (!haveIpk) {
            // The identity protection key of this fabric. Random once,
            // then kept: every device on the fabric holds a copy.
            if (Crypto::DRBG_get_bytes(ipk, sizeof(ipk)) != CHIP_NO_ERROR) {
                if (error)
                    *error = "no entropy for the fabric IPK";
                return false;
            }
            return saveRegistryLocked(error);
        }
        return true;
    }

    bool saveRegistryLocked(std::string *error)
    {
        Json::Value root(Json::objectValue);
        root["ipk"] = toHex(ipk, sizeof(ipk));
        root["nextNodeId"] = static_cast<Json::UInt64>(nextNodeId);
        Json::Value nodes(Json::arrayValue);
        for (const auto &[id, record] : registry) {
            Json::Value node(Json::objectValue);
            node["nodeId"] = static_cast<Json::UInt64>(record.nodeId);
            node["name"] = record.name;
            nodes.append(node);
        }
        root["nodes"] = nodes;

        const std::filesystem::path path = registryPath();
        const std::filesystem::path tmp = path.string() + ".tmp";
        {
            std::ofstream out(tmp, std::ios::trunc);
            if (!out) {
                if (error)
                    *error = "cannot write " + tmp.string();
                return false;
            }
            Json::StreamWriterBuilder builder;
            builder["indentation"] = "  ";
            out << Json::writeString(builder, root) << '\n';
        }
        std::error_code ec;
        std::filesystem::rename(tmp, path, ec);
        if (ec) {
            if (error)
                *error = "cannot replace " + path.string() + ": " + ec.message();
            return false;
        }
        return true;
    }

    std::uint64_t allocateNodeId()
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        return nextNodeId++;
    }

    void rememberNode(std::uint64_t nodeId, const std::string &name)
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        registry[nodeId] = NodeRecord{nodeId, name};
        std::string error;
        if (!saveRegistryLocked(&error))
            log(LogLevel::Error, "registry not saved: " + error);
    }

    // ---- stack --------------------------------------------------------

    bool bringUp(std::string *error)
    {
        auto fail = [&](const char *what, CHIP_ERROR err) {
            if (error)
                *error = std::string(what) + ": " + ErrorStr(err);
            return false;
        };

        CHIP_ERROR err = Platform::MemoryInit();
        if (err != CHIP_NO_ERROR)
            return fail("memory init", err);

        std::error_code ec;
        std::filesystem::create_directories(options.stateDir, ec);
        if (ec) {
            if (error)
                *error = "state directory " + options.stateDir + ": " + ec.message();
            return false;
        }

        if (!loadRegistry(error))
            return false;

        err = storage.Init("phi", options.stateDir.c_str());
        if (err != CHIP_NO_ERROR)
            return fail("storage init", err);
        err = operationalKeystore.Init(&storage);
        if (err != CHIP_NO_ERROR)
            return fail("operational keystore init", err);
        err = opCertStore.Init(&storage);
        if (err != CHIP_NO_ERROR)
            return fail("certificate store init", err);

        FactoryInitParams factoryParams;
        factoryParams.fabricIndependentStorage = &storage;
        factoryParams.operationalKeystore = &operationalKeystore;
        factoryParams.opCertStore = &opCertStore;
        factoryParams.enableServerInteractions = false;
        factoryParams.sessionKeystore = &sessionKeystore;
        factoryParams.dataModelProvider = CodegenDataModelProviderInstance(&storage);

        groupDataProvider.SetStorageDelegate(&storage);
        groupDataProvider.SetSessionKeystore(&sessionKeystore);
        err = groupDataProvider.Init();
        if (err != CHIP_NO_ERROR)
            return fail("group data provider init", err);
        Credentials::SetGroupDataProvider(&groupDataProvider);
        factoryParams.groupDataProvider = &groupDataProvider;

        err = DeviceControllerFactory::GetInstance().Init(factoryParams);
        if (err != CHIP_NO_ERROR)
            return fail("controller factory init", err);

        // Attestation: production PAAs from the package, the SDK's test roots
        // when there are none.
        if (!options.paaTrustStoreDir.empty()) {
            fileTrustStore = std::make_unique<Credentials::FileAttestationTrustStore>(options.paaTrustStoreDir.c_str());
            if (fileTrustStore->paaCount() > 0) {
                trustStore = fileTrustStore.get();
            } else {
                log(LogLevel::Warn, "no PAA certificates under " + options.paaTrustStoreDir + "; using the SDK test roots");
                fileTrustStore.reset();
            }
        }
        if (trustStore == nullptr)
            trustStore = Credentials::GetTestAttestationTrustStore();
        Credentials::SetDeviceAttestationCredentialsProvider(Credentials::Examples::GetExampleDACProvider());
        dacVerifier = Credentials::GetDefaultDACVerifier(trustStore);
        if (dacVerifier == nullptr)
            return fail("attestation verifier", CHIP_ERROR_INTERNAL);
        dacVerifier->EnableCdTestKeySupport(true);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        err = opCredsIssuer.Initialize(storage);
#pragma GCC diagnostic pop
        if (err != CHIP_NO_ERROR)
            return fail("credentials issuer init", err);

        const NodeId localNodeId = storage.GetLocalNodeId();
        Crypto::P256Keypair ephemeralKey;
        err = ephemeralKey.Initialize(Crypto::ECPKeyTarget::ECDSA);
        if (err != CHIP_NO_ERROR)
            return fail("operational key", err);

        MutableByteSpan nocSpan(noc);
        MutableByteSpan icacSpan(icac);
        MutableByteSpan rcacSpan(rcac);
        err = opCredsIssuer.GenerateNOCChainAfterValidation(localNodeId, kFabricId, kUndefinedCATs,
                                                            ephemeralKey.Pubkey(), rcacSpan, icacSpan, nocSpan);
        if (err != CHIP_NO_ERROR)
            return fail("controller certificate chain", err);

        SetupParams setup;
        setup.operationalCredentialsDelegate = &opCredsIssuer;
        setup.operationalKeypair = &ephemeralKey;
        setup.controllerRCAC = rcacSpan;
        setup.controllerICAC = icacSpan;
        setup.controllerNOC = nocSpan;
        setup.controllerVendorId = VendorId::TestVendor1;
        setup.pairingDelegate = this;
        setup.permitMultiControllerFabrics = true;
        setup.enableServerInteractions = false;
        setup.deviceAttestationVerifier = dacVerifier;

        commissioner = std::make_unique<DeviceCommissioner>();
        err = DeviceControllerFactory::GetInstance().SetupCommissioner(setup, *commissioner);
        if (err != CHIP_NO_ERROR)
            return fail("commissioner setup", err);

        const FabricIndex fabricIndex = commissioner->GetFabricIndex();
        std::uint8_t compressedFabricId[sizeof(std::uint64_t)];
        MutableByteSpan compressedSpan(compressedFabricId);
        err = commissioner->GetCompressedFabricIdBytes(compressedSpan);
        if (err != CHIP_NO_ERROR)
            return fail("compressed fabric id", err);
        err = Credentials::SetSingleIpkEpochKey(&groupDataProvider, fabricIndex, ByteSpan(ipk), compressedSpan);
        if (err != CHIP_NO_ERROR)
            return fail("fabric IPK", err);

        s_logTarget = this;
        Logging::SetLogRedirectCallback(&Impl::logRedirect);
        Logging::SetLogFilter(Logging::kLogCategory_Progress);

        err = DeviceLayer::PlatformMgr().StartEventLoopTask();
        if (err != CHIP_NO_ERROR)
            return fail("event loop", err);
        loopRunning = true;

        {
            char text[128];
            std::snprintf(text, sizeof(text), "fabric %u up: compressed id %s, %zu PAA roots, %zu known nodes",
                          static_cast<unsigned>(fabricIndex),
                          toHex(compressedFabricId, sizeof(compressedFabricId)).c_str(),
                          fileTrustStore ? fileTrustStore->paaCount() : std::size_t(0),
                          registry.size());
            log(LogLevel::Info, text);
        }
        return true;
    }

    void tearDown(int budgetMs)
    {
        if (loopRunning) {
            // Objects that live on the Matter thread die there.
            runSync([this] {
                subscriptions.clear();
                if (commissioning && commissioner)
                    (void)commissioner->StopPairing(commissioning->nodeId);
                commissioning.reset();
            }, budgetMs / 2);
            (void)DeviceLayer::PlatformMgr().StopEventLoopTask();
            loopRunning = false;
        }
        Logging::SetLogRedirectCallback(nullptr);
        s_logTarget = nullptr;
        if (commissioner) {
            commissioner->Shutdown();
            commissioner.reset();
        }
        DeviceControllerFactory::GetInstance().Shutdown();
        Platform::MemoryShutdown();
    }

    // ---- threading ----------------------------------------------------

    void post(std::function<void()> task)
    {
        auto *heap = new std::function<void()>(std::move(task));
        const CHIP_ERROR err = DeviceLayer::PlatformMgr().ScheduleWork(&runPosted, reinterpret_cast<intptr_t>(heap));
        if (err != CHIP_NO_ERROR) {
            delete heap;
            log(LogLevel::Error, std::string("cannot schedule work on the Matter thread: ") + ErrorStr(err));
        }
    }

    bool runSync(std::function<void()> task, int timeoutMs)
    {
        auto state = std::make_shared<std::pair<std::mutex, std::condition_variable>>();
        auto done = std::make_shared<bool>(false);
        post([state, done, task = std::move(task)] {
            task();
            std::lock_guard<std::mutex> lock(state->first);
            *done = true;
            state->second.notify_all();
        });
        std::unique_lock<std::mutex> lock(state->first);
        return state->second.wait_for(lock, std::chrono::milliseconds(timeoutMs), [&] { return *done; });
    }

    // ---- DevicePairingDelegate ---------------------------------------

    void finishCommissioning(CHIP_ERROR err)
    {
        if (!commissioning || commissioning->finished)
            return;
        commissioning->finished = true;
        auto job = std::move(commissioning);
        if (job->done)
            job->done(job->nodeId, err);
    }

    void OnPairingComplete(CHIP_ERROR error) override
    {
        if (error != CHIP_NO_ERROR) {
            log(LogLevel::Warn, std::string("PASE session failed: ") + ErrorStr(error));
            finishCommissioning(error);
        }
    }

    void OnCommissioningComplete(NodeId deviceId, CHIP_ERROR error) override
    {
        if (error == CHIP_NO_ERROR) {
            char text[96];
            std::snprintf(text, sizeof(text), "node 0x%016llx commissioned", static_cast<unsigned long long>(deviceId));
            log(LogLevel::Info, text);
        } else {
            log(LogLevel::Warn, std::string("commissioning failed: ") + ErrorStr(error));
        }
        finishCommissioning(error);
    }

    void OnCommissioningStatusUpdate(PeerId peerId, CommissioningStage stageCompleted, CHIP_ERROR error) override
    {
        (void)peerId;
        if (error == CHIP_NO_ERROR)
            return;
        std::string text = "commissioning stage ";
        text += StageToString(stageCompleted);
        text += ": ";
        text += ErrorStr(error);
        log(LogLevel::Debug, text);
    }

    // ---- DeviceAttestationDelegate -----------------------------------

    Optional<std::uint16_t> FailSafeExpiryTimeoutSecs() const override
    {
        return Optional<std::uint16_t>();
    }

    void OnDeviceAttestationCompleted(DeviceCommissioner *deviceCommissioner, DeviceProxy *device,
                                      const Credentials::DeviceAttestationVerifier::AttestationDeviceInfo &info,
                                      Credentials::AttestationVerificationResult attestationResult) override
    {
        (void)info;
        if (attestationResult == Credentials::AttestationVerificationResult::kSuccess)
            return;
        if (!allowUntrustedAttestation) {
            log(LogLevel::Warn, "device attestation failed and untrusted devices are not allowed");
            return;
        }
        log(LogLevel::Warn, "device attestation failed; continuing because untrusted devices are allowed");
        const CHIP_ERROR err = deviceCommissioner->ContinueCommissioningAfterDeviceAttestation(
            device, Credentials::AttestationVerificationResult::kSuccess);
        if (err != CHIP_NO_ERROR)
            finishCommissioning(err);
    }

    // ---- session helper ----------------------------------------------

    struct Connect {
        Impl *self = nullptr;
        std::function<void(Messaging::ExchangeManager &, const SessionHandle &)> connected;
        std::function<void(CHIP_ERROR)> failed;
        Callback::Callback<OnDeviceConnected> onConnected;
        Callback::Callback<OnDeviceConnectionFailure> onFailure;

        Connect() : onConnected(&Connect::connectedFn, this), onFailure(&Connect::failureFn, this) {}

        static void connectedFn(void *context, Messaging::ExchangeManager &exchangeMgr, const SessionHandle &session)
        {
            std::unique_ptr<Connect> self(static_cast<Connect *>(context));
            self->connected(exchangeMgr, session);
        }

        static void failureFn(void *context, const ScopedNodeId &peerId, CHIP_ERROR error)
        {
            (void)peerId;
            std::unique_ptr<Connect> self(static_cast<Connect *>(context));
            self->failed(error);
        }
    };

    void withSession(std::uint64_t nodeId,
                     std::function<void(Messaging::ExchangeManager &, const SessionHandle &)> connected,
                     std::function<void(CHIP_ERROR)> failed)
    {
        auto *request = new Connect();
        request->self = this;
        request->connected = std::move(connected);
        request->failed = std::move(failed);
        const CHIP_ERROR err = commissioner->GetConnectedDevice(nodeId, &request->onConnected, &request->onFailure);
        if (err != CHIP_NO_ERROR) {
            std::unique_ptr<Connect> owned(request);
            owned->failed(err);
        }
    }

    // ---- describe -----------------------------------------------------

    struct Describe : public ReadClient::Callback {
        Impl *self = nullptr;
        NodeInfo info;
        std::function<void(const NodeInfo &, CHIP_ERROR)> done;
        std::map<std::uint16_t, EndpointInfo> endpoints;
        std::unique_ptr<ReadClient> client;
        AttributePathParams paths[9];
        CHIP_ERROR result = CHIP_NO_ERROR;

        EndpointInfo &endpoint(EndpointId id)
        {
            EndpointInfo &ep = endpoints[id];
            ep.endpoint = id;
            return ep;
        }

        void OnAttributeData(const ConcreteDataAttributePath &path, TLV::TLVReader *data, const StatusIB &status) override
        {
            if (!status.IsSuccess() || data == nullptr)
                return;
            using namespace chip::app::Clusters;
            CHIP_ERROR err = CHIP_NO_ERROR;
            if (path.mClusterId == Descriptor::Id) {
                if (path.mAttributeId == Descriptor::Attributes::DeviceTypeList::Id) {
                    auto &list = endpoint(path.mEndpointId).deviceTypes;
                    if (path.IsListItemOperation()) {
                        Descriptor::Structs::DeviceTypeStruct::DecodableType item;
                        err = DataModel::Decode(*data, item);
                        if (err == CHIP_NO_ERROR)
                            list.push_back(item.deviceType);
                    } else {
                        Descriptor::Attributes::DeviceTypeList::TypeInfo::DecodableType decoded;
                        err = DataModel::Decode(*data, decoded);
                        if (err == CHIP_NO_ERROR) {
                            list.clear();
                            auto it = decoded.begin();
                            while (it.Next())
                                list.push_back(it.GetValue().deviceType);
                        }
                    }
                } else if (path.mAttributeId == Descriptor::Attributes::ServerList::Id) {
                    auto &list = endpoint(path.mEndpointId).serverClusters;
                    if (path.IsListItemOperation()) {
                        ClusterId item = 0;
                        err = DataModel::Decode(*data, item);
                        if (err == CHIP_NO_ERROR)
                            list.push_back(item);
                    } else {
                        Descriptor::Attributes::ServerList::TypeInfo::DecodableType decoded;
                        err = DataModel::Decode(*data, decoded);
                        if (err == CHIP_NO_ERROR) {
                            list.clear();
                            auto it = decoded.begin();
                            while (it.Next())
                                list.push_back(it.GetValue());
                        }
                    }
                }
            } else if (path.mClusterId == BasicInformation::Id && path.mEndpointId == 0) {
                CharSpan text;
                err = DataModel::Decode(*data, text);
                if (err == CHIP_NO_ERROR) {
                    if (path.mAttributeId == BasicInformation::Attributes::VendorName::Id)
                        info.vendor = spanToString(text);
                    else if (path.mAttributeId == BasicInformation::Attributes::ProductName::Id)
                        info.product = spanToString(text);
                    else if (path.mAttributeId == BasicInformation::Attributes::NodeLabel::Id)
                        info.label = spanToString(text);
                    else if (path.mAttributeId == BasicInformation::Attributes::SoftwareVersionString::Id)
                        info.software = spanToString(text);
                }
            } else if (path.mClusterId == BridgedDeviceBasicInformation::Id) {
                CharSpan text;
                err = DataModel::Decode(*data, text);
                if (err == CHIP_NO_ERROR) {
                    EndpointInfo &ep = endpoint(path.mEndpointId);
                    if (path.mAttributeId == BridgedDeviceBasicInformation::Attributes::NodeLabel::Id)
                        ep.label = spanToString(text);
                    else if (path.mAttributeId == BridgedDeviceBasicInformation::Attributes::VendorName::Id)
                        ep.vendor = spanToString(text);
                    else if (path.mAttributeId == BridgedDeviceBasicInformation::Attributes::ProductName::Id)
                        ep.product = spanToString(text);
                }
            }
            if (err != CHIP_NO_ERROR) {
                char text[128];
                std::snprintf(text, sizeof(text), "describe: endpoint %u cluster 0x%04x attribute 0x%04x: %s",
                              static_cast<unsigned>(path.mEndpointId), static_cast<unsigned>(path.mClusterId),
                              static_cast<unsigned>(path.mAttributeId), ErrorStr(err));
                self->log(LogLevel::Debug, text);
            }
        }

        void OnError(CHIP_ERROR error) override
        {
            result = error;
        }

        void OnDone(ReadClient *) override
        {
            for (auto &[id, ep] : endpoints)
                info.endpoints.push_back(ep);
            auto finish = std::move(done);
            NodeInfo out = std::move(info);
            const CHIP_ERROR err = result;
            Impl *owner = self;
            // The ReadClient is done with us once OnDone returns; free both on
            // the next turn of the loop.
            owner->post([this] { delete this; });
            if (finish)
                finish(out, err);
        }
    };

    void describe(std::uint64_t nodeId, std::function<void(const NodeInfo &, CHIP_ERROR)> done)
    {
        auto *read = new Describe();
        read->self = this;
        read->info.nodeId = nodeId;
        read->done = std::move(done);
        withSession(nodeId,
            [this, read](Messaging::ExchangeManager &exchangeMgr, const SessionHandle &session) {
                using namespace chip::app::Clusters;
                read->paths[0] = AttributePathParams(kInvalidEndpointId, Descriptor::Id, Descriptor::Attributes::DeviceTypeList::Id);
                read->paths[1] = AttributePathParams(kInvalidEndpointId, Descriptor::Id, Descriptor::Attributes::ServerList::Id);
                read->paths[2] = AttributePathParams(0, BasicInformation::Id, BasicInformation::Attributes::VendorName::Id);
                read->paths[3] = AttributePathParams(0, BasicInformation::Id, BasicInformation::Attributes::ProductName::Id);
                read->paths[4] = AttributePathParams(0, BasicInformation::Id, BasicInformation::Attributes::NodeLabel::Id);
                read->paths[5] = AttributePathParams(0, BasicInformation::Id, BasicInformation::Attributes::SoftwareVersionString::Id);
                read->paths[6] = AttributePathParams(kInvalidEndpointId, BridgedDeviceBasicInformation::Id,
                                                     BridgedDeviceBasicInformation::Attributes::NodeLabel::Id);
                read->paths[7] = AttributePathParams(kInvalidEndpointId, BridgedDeviceBasicInformation::Id,
                                                     BridgedDeviceBasicInformation::Attributes::VendorName::Id);
                read->paths[8] = AttributePathParams(kInvalidEndpointId, BridgedDeviceBasicInformation::Id,
                                                     BridgedDeviceBasicInformation::Attributes::ProductName::Id);
                ReadPrepareParams params(session);
                params.mpAttributePathParamsList = read->paths;
                params.mAttributePathParamsListSize = std::size(read->paths);
                params.mIsFabricFiltered = false;
                read->client = std::make_unique<ReadClient>(InteractionModelEngine::GetInstance(), &exchangeMgr, *read,
                                                            ReadClient::InteractionType::Read);
                const CHIP_ERROR err = read->client->SendRequest(params);
                if (err != CHIP_NO_ERROR) {
                    auto finish = std::move(read->done);
                    NodeInfo info = read->info;
                    delete read;
                    if (finish)
                        finish(info, err);
                }
            },
            [read](CHIP_ERROR err) {
                auto finish = std::move(read->done);
                NodeInfo info = read->info;
                delete read;
                if (finish)
                    finish(info, err);
            });
    }

    // ---- subscription -------------------------------------------------

    struct Subscription : public ReadClient::Callback {
        Impl *self = nullptr;
        std::uint64_t nodeId = 0;
        std::unique_ptr<ReadClient> client;
        bool established = false;

        void OnAttributeData(const ConcreteDataAttributePath &path, TLV::TLVReader *data, const StatusIB &status) override
        {
            using namespace chip::app::Clusters;
            if (!status.IsSuccess() || data == nullptr)
                return;
            if (path.mClusterId != OnOff::Id || path.mAttributeId != OnOff::Attributes::OnOff::Id)
                return;
            bool on = false;
            if (DataModel::Decode(*data, on) != CHIP_NO_ERROR)
                return;
            if (self->callbacks.onOff)
                self->callbacks.onOff(nodeId, path.mEndpointId, on);
        }

        void OnSubscriptionEstablished(SubscriptionId) override
        {
            established = true;
            if (self->callbacks.reachable)
                self->callbacks.reachable(nodeId, true);
        }

        CHIP_ERROR OnResubscriptionNeeded(ReadClient *readClient, CHIP_ERROR cause) override
        {
            if (established && self->callbacks.reachable)
                self->callbacks.reachable(nodeId, false);
            established = false;
            char text[96];
            std::snprintf(text, sizeof(text), "node 0x%016llx: subscription dropped (%s), resubscribing",
                          static_cast<unsigned long long>(nodeId), ErrorStr(cause));
            self->log(LogLevel::Debug, text);
            return readClient->DefaultResubscribePolicy(cause);
        }

        void OnError(CHIP_ERROR error) override
        {
            char text[96];
            std::snprintf(text, sizeof(text), "node 0x%016llx: subscription error %s",
                          static_cast<unsigned long long>(nodeId), ErrorStr(error));
            self->log(LogLevel::Debug, text);
        }

        void OnDone(ReadClient *) override {}

        void OnDeallocatePaths(ReadPrepareParams &&params) override
        {
            delete[] params.mpAttributePathParamsList;
            params.mpAttributePathParamsList = nullptr;
            params.mAttributePathParamsListSize = 0;
        }
    };

    std::map<std::uint64_t, std::unique_ptr<Subscription>> subscriptions;

    void subscribeOnOff(std::uint64_t nodeId)
    {
        if (subscriptions.count(nodeId))
            return;
        auto sub = std::make_unique<Subscription>();
        sub->self = this;
        sub->nodeId = nodeId;
        Subscription *raw = sub.get();
        subscriptions[nodeId] = std::move(sub);

        withSession(nodeId,
            [this, raw](Messaging::ExchangeManager &exchangeMgr, const SessionHandle &session) {
                using namespace chip::app::Clusters;
                auto *paths = new AttributePathParams[1];
                paths[0] = AttributePathParams(kInvalidEndpointId, OnOff::Id, OnOff::Attributes::OnOff::Id);
                ReadPrepareParams params(session);
                params.mpAttributePathParamsList = paths;
                params.mAttributePathParamsListSize = 1;
                params.mMinIntervalFloorSeconds = kSubscribeMinIntervalSeconds;
                params.mMaxIntervalCeilingSeconds = kSubscribeMaxIntervalSeconds;
                params.mKeepSubscriptions = true;
                params.mIsFabricFiltered = false;
                raw->client = std::make_unique<ReadClient>(InteractionModelEngine::GetInstance(), &exchangeMgr, *raw,
                                                           ReadClient::InteractionType::Subscribe);
                const CHIP_ERROR err = raw->client->SendAutoResubscribeRequest(std::move(params));
                if (err != CHIP_NO_ERROR) {
                    char text[96];
                    std::snprintf(text, sizeof(text), "node 0x%016llx: cannot subscribe: %s",
                                  static_cast<unsigned long long>(raw->nodeId), ErrorStr(err));
                    log(LogLevel::Warn, text);
                    subscriptions.erase(raw->nodeId);
                }
            },
            [this, raw](CHIP_ERROR err) {
                char text[96];
                std::snprintf(text, sizeof(text), "node 0x%016llx: not reachable for subscription: %s",
                              static_cast<unsigned long long>(raw->nodeId), ErrorStr(err));
                log(LogLevel::Warn, text);
                if (callbacks.reachable)
                    callbacks.reachable(raw->nodeId, false);
                subscriptions.erase(raw->nodeId);
            });
    }

    // ---- commands -----------------------------------------------------

    void setOnOff(std::uint64_t nodeId, std::uint16_t endpoint, bool on, std::function<void(CHIP_ERROR)> done)
    {
        auto shared = std::make_shared<std::function<void(CHIP_ERROR)>>(std::move(done));
        withSession(nodeId,
            [endpoint, on, shared](Messaging::ExchangeManager &exchangeMgr, const SessionHandle &session) {
                using namespace chip::app::Clusters;
                auto onSuccess = [shared](const ConcreteCommandPath &, const StatusIB &, const DataModel::NullObjectType &) {
                    (*shared)(CHIP_NO_ERROR);
                };
                auto onError = [shared](CHIP_ERROR err) { (*shared)(err); };
                CHIP_ERROR err;
                if (on)
                    err = InvokeCommandRequest(&exchangeMgr, session, endpoint, OnOff::Commands::On::Type{}, onSuccess, onError);
                else
                    err = InvokeCommandRequest(&exchangeMgr, session, endpoint, OnOff::Commands::Off::Type{}, onSuccess, onError);
                if (err != CHIP_NO_ERROR)
                    (*shared)(err);
            },
            [shared](CHIP_ERROR err) { (*shared)(err); });
    }

    // ---- commissioning ------------------------------------------------

    void commission(const std::string &setupCode, std::function<void(std::uint64_t, CHIP_ERROR)> done)
    {
        if (commissioning) {
            done(0, CHIP_ERROR_BUSY);
            return;
        }
        auto job = std::make_unique<Commissioning>();
        job->nodeId = allocateNodeId();
        job->done = std::move(done);
        commissioning = std::move(job);

        commissioningParams = CommissioningParameters();
        commissioningParams.SetDeviceAttestationDelegate(this);

        char text[96];
        std::snprintf(text, sizeof(text), "commissioning node 0x%016llx over the network",
                      static_cast<unsigned long long>(commissioning->nodeId));
        log(LogLevel::Info, text);

        const CHIP_ERROR err = commissioner->PairDevice(commissioning->nodeId, setupCode.c_str(), commissioningParams,
                                                        DiscoveryType::kDiscoveryNetworkOnly);
        if (err != CHIP_NO_ERROR)
            finishCommissioning(err);
    }
};

Controller::Impl *Controller::Impl::s_logTarget = nullptr;

// ---------------------------------------------------------------------------

Controller::Controller() : m_impl(std::make_unique<Impl>()) {}

Controller::~Controller() = default;

bool Controller::start(const Options &options, Callbacks callbacks, std::string *error)
{
    m_impl->options = options;
    m_impl->callbacks = std::move(callbacks);
    m_impl->allowUntrustedAttestation = options.allowUntrustedAttestation;
    return m_impl->bringUp(error);
}

void Controller::stop(int budgetMs)
{
    m_impl->tearDown(budgetMs);
}

void Controller::setAllowUntrustedAttestation(bool allow)
{
    m_impl->allowUntrustedAttestation = allow;
}

std::vector<std::uint64_t> Controller::nodes() const
{
    std::lock_guard<std::mutex> lock(m_impl->registryMutex);
    std::vector<std::uint64_t> out;
    for (const auto &[id, record] : m_impl->registry)
        out.push_back(id);
    return out;
}

void Controller::commission(const std::string &setupCode, std::function<void(std::uint64_t, CHIP_ERROR)> done)
{
    m_impl->post([this, setupCode, done = std::move(done)]() mutable {
        m_impl->commission(setupCode, [this, done = std::move(done)](std::uint64_t nodeId, CHIP_ERROR err) {
            if (err == CHIP_NO_ERROR)
                m_impl->rememberNode(nodeId, "");
            done(nodeId, err);
        });
    });
}

void Controller::describe(std::uint64_t nodeId, std::function<void(const NodeInfo &, CHIP_ERROR)> done)
{
    m_impl->post([this, nodeId, done = std::move(done)]() mutable { m_impl->describe(nodeId, std::move(done)); });
}

void Controller::subscribeOnOff(std::uint64_t nodeId)
{
    m_impl->post([this, nodeId] { m_impl->subscribeOnOff(nodeId); });
}

void Controller::setOnOff(std::uint64_t nodeId, std::uint16_t endpoint, bool on, std::function<void(CHIP_ERROR)> done)
{
    m_impl->post([this, nodeId, endpoint, on, done = std::move(done)]() mutable {
        m_impl->setOnOff(nodeId, endpoint, on, std::move(done));
    });
}

void Controller::post(std::function<void()> task)
{
    m_impl->post(std::move(task));
}

} // namespace phimatter
