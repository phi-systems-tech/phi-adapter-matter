#include "controller.h"

#include <controller/CommissioningWindowOpener.h>
#include <controller/CurrentFabricRemover.h>
#include <controller/WriteInteraction.h>
#include <setup_payload/ManualSetupPayloadGenerator.h>
#include <setup_payload/QRCodeSetupPayloadGenerator.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <cstdlib>
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
// How long a commissioning attempt may run. The SDK's pairer waits for a
// commissionable node with the code's discriminator for as long as it is
// asked to; a device whose window is shut never answers, and without a
// deadline the attempt would sit there and block the next one.
constexpr std::uint32_t kCommissioningDeadlineSeconds = 90;
// PBKDF iterations for the window's PASE verifier; the spec allows 1000..100000.
constexpr std::uint32_t kSpake2pIterations = 1000;

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

// The example issuer hands every device the SDK's well-known test IPK. The
// device then computes CASE destination identifiers with that key while the
// controller computes them with the fabric's own, and the two never meet
// ("No shared trusted root" from the device). This delegate lets the example
// issuer do the certificate work and replaces the key on the way back.
class IssuerWithFabricIpk final : public OperationalCredentialsDelegate
{
public:
    IssuerWithFabricIpk(ExampleOperationalCredentialsIssuer &inner, const std::uint8_t *ipk, std::size_t ipkSize)
        : m_inner(inner), m_ipk(ipk, ipkSize), m_bridge(&IssuerWithFabricIpk::onChain, this)
    {}

    CHIP_ERROR GenerateNOCChain(const ByteSpan &csrElements, const ByteSpan &csrNonce, const ByteSpan &attestationSignature,
                                const ByteSpan &attestationChallenge, const ByteSpan &dac, const ByteSpan &pai,
                                Callback::Callback<OnNOCChainGeneration> *onCompletion) override
    {
        m_pending = onCompletion;
        return m_inner.GenerateNOCChain(csrElements, csrNonce, attestationSignature, attestationChallenge, dac, pai, &m_bridge);
    }

    void SetNodeIdForNextNOCRequest(NodeId nodeId) override { m_inner.SetNodeIdForNextNOCRequest(nodeId); }
    void SetFabricIdForNextNOCRequest(FabricId fabricId) override { m_inner.SetFabricIdForNextNOCRequest(fabricId); }

private:
    static void onChain(void *context, CHIP_ERROR status, const ByteSpan &noc, const ByteSpan &icac, const ByteSpan &rcac,
                        Optional<Crypto::IdentityProtectionKeySpan>, Optional<NodeId> adminSubject)
    {
        auto *self = static_cast<IssuerWithFabricIpk *>(context);
        Callback::Callback<OnNOCChainGeneration> *pending = self->m_pending;
        self->m_pending = nullptr;
        if (pending == nullptr)
            return;
        pending->mCall(pending->mContext, status, noc, icac, rcac,
                       MakeOptional(Crypto::IdentityProtectionKeySpan(self->m_ipk.data())), adminSubject);
    }

    ExampleOperationalCredentialsIssuer &m_inner;
    ByteSpan m_ipk;
    Callback::Callback<OnNOCChainGeneration> *m_pending = nullptr;
    Callback::Callback<OnNOCChainGeneration> m_bridge;
};

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
    std::unique_ptr<IssuerWithFabricIpk> credentialsDelegate;
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
    std::map<std::string, std::string> deviceNames;
    std::uint64_t nextNodeId = 1;
    std::uint8_t ipk[Crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES];
    std::string compressedFabricIdHex;

    // Commissioning in flight. Matter thread only.
    struct Commissioning {
        std::uint64_t nodeId = 0;
        std::function<void(std::uint64_t, CHIP_ERROR)> done;
        bool finished = false;
    };
    std::unique_ptr<Commissioning> commissioning;
    CommissioningParameters commissioningParams;
    // The SDK keeps a span into this for the length of the commissioning.
    std::vector<std::uint8_t> commissioningDataset;

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
            deviceNames.clear();
            if (root.isMember("names") && root["names"].isObject()) {
                for (const std::string &key : root["names"].getMemberNames())
                    deviceNames[key] = root["names"][key].asString();
            }
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
        Json::Value names(Json::objectValue);
        for (const auto &[id, name] : deviceNames)
            names[id] = name;
        root["names"] = names;

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

    void setDeviceName(const std::string &deviceId, const std::string &name)
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        if (name.empty())
            deviceNames.erase(deviceId);
        else
            deviceNames[deviceId] = name;
        std::string error;
        if (!saveRegistryLocked(&error))
            log(LogLevel::Error, "registry not saved: " + error);
    }

    std::string deviceName(const std::string &deviceId) const
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        const auto it = deviceNames.find(deviceId);
        return it == deviceNames.end() ? std::string() : it->second;
    }

    void forgetNode(std::uint64_t nodeId)
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        if (registry.erase(nodeId) == 0)
            return;
        // The node's devices are gone with it, names included.
        char prefix[32];
        std::snprintf(prefix, sizeof(prefix), "n%llx-e", static_cast<unsigned long long>(nodeId));
        for (auto it = deviceNames.begin(); it != deviceNames.end();) {
            if (it->first.rfind(prefix, 0) == 0)
                it = deviceNames.erase(it);
            else
                ++it;
        }
        std::string error;
        if (!saveRegistryLocked(&error))
            log(LogLevel::Error, "registry not saved: " + error);
    }

    bool registryEmpty() const
    {
        std::lock_guard<std::mutex> lock(registryMutex);
        return registry.empty();
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

        // The SDK's PosixConfig keeps chip_factory/config/counters.ini under
        // /tmp for every CHIP process on the host unless told otherwise
        // (phi-chip patch): this instance keeps its own set in its state dir.
        ::setenv("CHIP_CONFIG_DIR", options.stateDir.c_str(), 1);

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
        factoryParams.listenPort = options.listenPort;
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

        const NodeId localNodeId = controllerNodeId();
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

        credentialsDelegate = std::make_unique<IssuerWithFabricIpk>(opCredsIssuer, ipk, sizeof(ipk));

        SetupParams setup;
        setup.operationalCredentialsDelegate = credentialsDelegate.get();
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
        compressedFabricIdHex = toHex(compressedFabricId, sizeof(compressedFabricId));

        s_logTarget = this;
        Logging::SetLogRedirectCallback(&Impl::logRedirect);
        Logging::SetLogFilter(Logging::kLogCategory_Progress);

        err = DeviceLayer::PlatformMgr().StartEventLoopTask();
        if (err != CHIP_NO_ERROR)
            return fail("event loop", err);
        loopRunning = true;

        {
            char text[128];
            std::snprintf(text, sizeof(text),
                          "fabric %u up: compressed id %s, controller node 0x%016llx, %zu PAA roots, %zu known nodes",
                          static_cast<unsigned>(fabricIndex),
                          toHex(compressedFabricId, sizeof(compressedFabricId)).c_str(),
                          static_cast<unsigned long long>(localNodeId),
                          fileTrustStore ? fileTrustStore->paaCount() : std::size_t(0),
                          registry.size());
            log(LogLevel::Info, text);
        }
        return true;
    }

    // The controller's own operational node id. The example storage answers
    // the SDK's test id when none is stored, and every commissioned device
    // carries that id in its ACL; so a fabric that already has devices keeps
    // whatever it was built with, and only a fresh one draws a random id.
    NodeId controllerNodeId()
    {
        std::uint64_t stored = 0;
        std::uint16_t size = sizeof(stored);
        const CHIP_ERROR err = storage.SyncGetKeyValue("LocalNodeId", &stored, size);
        if (err == CHIP_NO_ERROR)
            return storage.GetLocalNodeId();
        NodeId nodeId = storage.GetLocalNodeId();
        if (registryEmpty()) {
            std::uint64_t random = 0;
            if (Crypto::DRBG_get_bytes(reinterpret_cast<std::uint8_t *>(&random), sizeof(random)) == CHIP_NO_ERROR)
                nodeId = static_cast<NodeId>(random % kMaxOperationalNodeId) + 1;
        }
        // Pinned either way, so the answer never changes underneath the ACLs.
        if (storage.SetLocalNodeId(nodeId) != CHIP_NO_ERROR)
            log(LogLevel::Warn, "controller node id not persisted; using the SDK default");
        return nodeId;
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

    static void onCommissioningDeadline(System::Layer *, void *appState)
    {
        auto *self = static_cast<Impl *>(appState);
        if (!self->commissioning || self->commissioning->finished)
            return;
        self->log(LogLevel::Warn, "commissioning: no device answered within the deadline; is its commissioning window open?");
        (void)self->commissioner->StopPairing(self->commissioning->nodeId);
        self->finishCommissioning(CHIP_ERROR_TIMEOUT);
    }

    void finishCommissioning(CHIP_ERROR err)
    {
        if (!commissioning || commissioning->finished)
            return;
        commissioning->finished = true;
        DeviceLayer::SystemLayer().CancelTimer(&Impl::onCommissioningDeadline, this);
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
        AttributePathParams paths[12];
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
            } else if (path.mClusterId == ColorControl::Id) {
                EndpointInfo &ep = endpoint(path.mEndpointId);
                if (path.mAttributeId == ColorControl::Attributes::ColorCapabilities::Id) {
                    ColorControl::Attributes::ColorCapabilities::TypeInfo::DecodableType caps;
                    err = DataModel::Decode(*data, caps);
                    if (err == CHIP_NO_ERROR)
                        ep.colorCapabilities = caps.Raw();
                } else {
                    std::uint16_t mireds = 0;
                    err = DataModel::Decode(*data, mireds);
                    if (err == CHIP_NO_ERROR) {
                        if (path.mAttributeId == ColorControl::Attributes::ColorTempPhysicalMinMireds::Id)
                            ep.colorTempMinMireds = mireds;
                        else if (path.mAttributeId == ColorControl::Attributes::ColorTempPhysicalMaxMireds::Id)
                            ep.colorTempMaxMireds = mireds;
                    }
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
                read->paths[9] = AttributePathParams(kInvalidEndpointId, ColorControl::Id,
                                                     ColorControl::Attributes::ColorCapabilities::Id);
                read->paths[10] = AttributePathParams(kInvalidEndpointId, ColorControl::Id,
                                                      ColorControl::Attributes::ColorTempPhysicalMinMireds::Id);
                read->paths[11] = AttributePathParams(kInvalidEndpointId, ColorControl::Id,
                                                      ColorControl::Attributes::ColorTempPhysicalMaxMireds::Id);
                if (session->IsSecureSession()) {
                    char address[Inet::IPAddress::kMaxStringLength] = {};
                    session->AsSecureSession()->GetPeerAddress().GetIPAddress().ToString(address, sizeof(address));
                    read->info.address = address;
                }
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
        bool primed = false;

        void OnAttributeData(const ConcreteDataAttributePath &path, TLV::TLVReader *data, const StatusIB &status) override
        {
            using namespace chip::app::Clusters;
            if (!status.IsSuccess() || data == nullptr)
                return;
            if (path.mClusterId == Descriptor::Id && path.mAttributeId == Descriptor::Attributes::PartsList::Id) {
                // Reported once when the subscription comes up and again
                // whenever a bridge's set of endpoints changes.
                if (primed && self->callbacks.topologyChanged)
                    self->callbacks.topologyChanged(nodeId);
                return;
            }
            AttributeValue value;
            if (!decode(path, *data, value))
                return;
            if (self->callbacks.attribute)
                self->callbacks.attribute(nodeId, path.mEndpointId, path.mClusterId, path.mAttributeId, value);
        }

        template <typename T>
        static bool decodePlain(TLV::TLVReader &data, AttributeValue &out)
        {
            T decoded{};
            if (DataModel::Decode(data, decoded) != CHIP_NO_ERROR)
                return false;
            out.number = static_cast<double>(decoded);
            return true;
        }

        template <typename T>
        static bool decodeNullable(TLV::TLVReader &data, AttributeValue &out)
        {
            DataModel::Nullable<T> decoded;
            if (DataModel::Decode(data, decoded) != CHIP_NO_ERROR)
                return false;
            out.isNull = decoded.IsNull();
            out.number = decoded.IsNull() ? 0.0 : static_cast<double>(decoded.Value());
            return true;
        }

        static bool decode(const ConcreteDataAttributePath &path, TLV::TLVReader &data, AttributeValue &out)
        {
            using namespace chip::app::Clusters;
            const ClusterId cluster = path.mClusterId;
            const AttributeId attribute = path.mAttributeId;
            if ((cluster == OnOff::Id && attribute == OnOff::Attributes::OnOff::Id)
                || (cluster == BooleanState::Id && attribute == BooleanState::Attributes::StateValue::Id)) {
                bool b = false;
                if (DataModel::Decode(data, b) != CHIP_NO_ERROR)
                    return false;
                out.boolean = b;
                out.number = b ? 1.0 : 0.0;
                return true;
            }
            if (cluster == OccupancySensing::Id && attribute == OccupancySensing::Attributes::Occupancy::Id) {
                OccupancySensing::Attributes::Occupancy::TypeInfo::DecodableType bits;
                if (DataModel::Decode(data, bits) != CHIP_NO_ERROR)
                    return false;
                out.boolean = bits.Has(OccupancySensing::OccupancyBitmap::kOccupied);
                out.number = out.boolean ? 1.0 : 0.0;
                return true;
            }
            if (cluster == PowerSource::Id && attribute == PowerSource::Attributes::BatPercentRemaining::Id)
                return decodeNullable<std::uint8_t>(data, out);
            if (cluster == LevelControl::Id && attribute == LevelControl::Attributes::CurrentLevel::Id)
                return decodeNullable<std::uint8_t>(data, out);
            if (cluster == TemperatureMeasurement::Id && attribute == TemperatureMeasurement::Attributes::MeasuredValue::Id)
                return decodeNullable<std::int16_t>(data, out);
            if (cluster == RelativeHumidityMeasurement::Id
                && attribute == RelativeHumidityMeasurement::Attributes::MeasuredValue::Id)
                return decodeNullable<std::uint16_t>(data, out);
            if (cluster == IlluminanceMeasurement::Id && attribute == IlluminanceMeasurement::Attributes::MeasuredValue::Id)
                return decodeNullable<std::uint16_t>(data, out);
            if (cluster == ColorControl::Id) {
                switch (attribute) {
                case ColorControl::Attributes::CurrentHue::Id:
                case ColorControl::Attributes::CurrentSaturation::Id:
                    return decodePlain<std::uint8_t>(data, out);
                case ColorControl::Attributes::CurrentX::Id:
                case ColorControl::Attributes::CurrentY::Id:
                case ColorControl::Attributes::ColorTemperatureMireds::Id:
                    return decodePlain<std::uint16_t>(data, out);
                case ColorControl::Attributes::ColorMode::Id: {
                    ColorControl::Attributes::ColorMode::TypeInfo::DecodableType mode;
                    if (DataModel::Decode(data, mode) != CHIP_NO_ERROR)
                        return false;
                    out.number = static_cast<double>(static_cast<std::uint8_t>(mode));
                    return true;
                }
                default:
                    return false;
                }
            }
            return false;
        }

        void OnReportEnd() override
        {
            // The first report is the priming report; the topology it carries
            // is the one describe() just read.
            primed = true;
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

    void subscribe(std::uint64_t nodeId)
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
                constexpr std::size_t kPathCount = 15;
                auto *paths = new AttributePathParams[kPathCount];
                paths[0] = AttributePathParams(kInvalidEndpointId, OnOff::Id, OnOff::Attributes::OnOff::Id);
                paths[1] = AttributePathParams(kInvalidEndpointId, BooleanState::Id, BooleanState::Attributes::StateValue::Id);
                paths[2] = AttributePathParams(kInvalidEndpointId, OccupancySensing::Id, OccupancySensing::Attributes::Occupancy::Id);
                paths[3] = AttributePathParams(kInvalidEndpointId, PowerSource::Id, PowerSource::Attributes::BatPercentRemaining::Id);
                paths[4] = AttributePathParams(kInvalidEndpointId, LevelControl::Id, LevelControl::Attributes::CurrentLevel::Id);
                paths[5] = AttributePathParams(kInvalidEndpointId, TemperatureMeasurement::Id,
                                               TemperatureMeasurement::Attributes::MeasuredValue::Id);
                paths[6] = AttributePathParams(kInvalidEndpointId, RelativeHumidityMeasurement::Id,
                                               RelativeHumidityMeasurement::Attributes::MeasuredValue::Id);
                paths[7] = AttributePathParams(kInvalidEndpointId, IlluminanceMeasurement::Id,
                                               IlluminanceMeasurement::Attributes::MeasuredValue::Id);
                paths[8] = AttributePathParams(0, Descriptor::Id, Descriptor::Attributes::PartsList::Id);
                paths[9] = AttributePathParams(kInvalidEndpointId, ColorControl::Id, ColorControl::Attributes::CurrentHue::Id);
                paths[10] = AttributePathParams(kInvalidEndpointId, ColorControl::Id,
                                                ColorControl::Attributes::CurrentSaturation::Id);
                paths[11] = AttributePathParams(kInvalidEndpointId, ColorControl::Id, ColorControl::Attributes::CurrentX::Id);
                paths[12] = AttributePathParams(kInvalidEndpointId, ColorControl::Id, ColorControl::Attributes::CurrentY::Id);
                paths[13] = AttributePathParams(kInvalidEndpointId, ColorControl::Id,
                                                ColorControl::Attributes::ColorTemperatureMireds::Id);
                paths[14] = AttributePathParams(kInvalidEndpointId, ColorControl::Id, ColorControl::Attributes::ColorMode::Id);
                ReadPrepareParams params(session);
                params.mpAttributePathParamsList = paths;
                params.mAttributePathParamsListSize = kPathCount;
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

    void setLevel(std::uint64_t nodeId, std::uint16_t endpoint, std::uint8_t level, std::function<void(CHIP_ERROR)> done)
    {
        auto shared = std::make_shared<std::function<void(CHIP_ERROR)>>(std::move(done));
        withSession(nodeId,
            [endpoint, level, shared](Messaging::ExchangeManager &exchangeMgr, const SessionHandle &session) {
                using namespace chip::app::Clusters;
                auto onSuccess = [shared](const ConcreteCommandPath &, const StatusIB &, const DataModel::NullObjectType &) {
                    (*shared)(CHIP_NO_ERROR);
                };
                auto onError = [shared](CHIP_ERROR err) { (*shared)(err); };
                LevelControl::Commands::MoveToLevelWithOnOff::Type command;
                command.level = level;
                command.transitionTime.SetNonNull(static_cast<std::uint16_t>(0));
                const CHIP_ERROR err = InvokeCommandRequest(&exchangeMgr, session, endpoint, command, onSuccess, onError);
                if (err != CHIP_NO_ERROR)
                    (*shared)(err);
            },
            [shared](CHIP_ERROR err) { (*shared)(err); });
    }

    void setColorTemperature(std::uint64_t nodeId, std::uint16_t endpoint, std::uint16_t mireds,
                             std::function<void(CHIP_ERROR)> done)
    {
        auto shared = std::make_shared<std::function<void(CHIP_ERROR)>>(std::move(done));
        withSession(nodeId,
            [endpoint, mireds, shared](Messaging::ExchangeManager &exchangeMgr, const SessionHandle &session) {
                using namespace chip::app::Clusters;
                auto onSuccess = [shared](const ConcreteCommandPath &, const StatusIB &, const DataModel::NullObjectType &) {
                    (*shared)(CHIP_NO_ERROR);
                };
                auto onError = [shared](CHIP_ERROR err) { (*shared)(err); };
                ColorControl::Commands::MoveToColorTemperature::Type command;
                command.colorTemperatureMireds = mireds;
                command.transitionTime = 0;
                const CHIP_ERROR err = InvokeCommandRequest(&exchangeMgr, session, endpoint, command, onSuccess, onError);
                if (err != CHIP_NO_ERROR)
                    (*shared)(err);
            },
            [shared](CHIP_ERROR err) { (*shared)(err); });
    }

    void setHueSaturation(std::uint64_t nodeId, std::uint16_t endpoint, std::uint8_t hue, std::uint8_t saturation,
                          std::function<void(CHIP_ERROR)> done)
    {
        auto shared = std::make_shared<std::function<void(CHIP_ERROR)>>(std::move(done));
        withSession(nodeId,
            [endpoint, hue, saturation, shared](Messaging::ExchangeManager &exchangeMgr, const SessionHandle &session) {
                using namespace chip::app::Clusters;
                auto onSuccess = [shared](const ConcreteCommandPath &, const StatusIB &, const DataModel::NullObjectType &) {
                    (*shared)(CHIP_NO_ERROR);
                };
                auto onError = [shared](CHIP_ERROR err) { (*shared)(err); };
                ColorControl::Commands::MoveToHueAndSaturation::Type command;
                command.hue = hue;
                command.saturation = saturation;
                command.transitionTime = 0;
                const CHIP_ERROR err = InvokeCommandRequest(&exchangeMgr, session, endpoint, command, onSuccess, onError);
                if (err != CHIP_NO_ERROR)
                    (*shared)(err);
            },
            [shared](CHIP_ERROR err) { (*shared)(err); });
    }

    void setFabricLabel(std::uint64_t nodeId, const std::string &label, std::function<void(CHIP_ERROR)> done)
    {
        auto shared = std::make_shared<std::function<void(CHIP_ERROR)>>(std::move(done));
        auto text = std::make_shared<std::string>(label.substr(0, 32));
        withSession(nodeId,
            [text, shared](Messaging::ExchangeManager &exchangeMgr, const SessionHandle &session) {
                using namespace chip::app::Clusters;
                auto onSuccess = [shared](const ConcreteCommandPath &, const StatusIB &,
                                          const OperationalCredentials::Commands::NOCResponse::DecodableType &) {
                    (*shared)(CHIP_NO_ERROR);
                };
                auto onError = [shared](CHIP_ERROR err) { (*shared)(err); };
                OperationalCredentials::Commands::UpdateFabricLabel::Type command;
                command.label = CharSpan(text->data(), text->size());
                const CHIP_ERROR err = InvokeCommandRequest(&exchangeMgr, session, 0, command, onSuccess, onError);
                if (err != CHIP_NO_ERROR)
                    (*shared)(err);
            },
            [shared](CHIP_ERROR err) { (*shared)(err); });
    }

    void setNodeLabel(std::uint64_t nodeId, const std::string &label, std::function<void(CHIP_ERROR)> done)
    {
        auto shared = std::make_shared<std::function<void(CHIP_ERROR)>>(std::move(done));
        auto text = std::make_shared<std::string>(label.substr(0, 32));
        withSession(nodeId,
            [text, shared](Messaging::ExchangeManager &, const SessionHandle &session) {
                using namespace chip::app::Clusters;
                auto onSuccess = [shared](const ConcreteAttributePath &) { (*shared)(CHIP_NO_ERROR); };
                auto onError = [shared](const ConcreteAttributePath *, CHIP_ERROR err) { (*shared)(err); };
                const CHIP_ERROR err = WriteAttribute<CharSpan>(session, 0, BasicInformation::Id,
                                                                BasicInformation::Attributes::NodeLabel::Id,
                                                                CharSpan(text->data(), text->size()), onSuccess, onError,
                                                                NullOptional);
                if (err != CHIP_NO_ERROR)
                    (*shared)(err);
            },
            [shared](CHIP_ERROR err) { (*shared)(err); });
    }

    // ---- sharing ------------------------------------------------------

    struct Share {
        Impl *self = nullptr;
        std::uint64_t nodeId = 0;
        std::function<void(const std::string &, const std::string &, CHIP_ERROR)> done;
        std::unique_ptr<CommissioningWindowOpener> opener;
        Callback::Callback<OnOpenCommissioningWindow> callback;

        Share() : callback(&Share::onOpened, this) {}

        static void onOpened(void *context, NodeId, CHIP_ERROR status, SetupPayload payload)
        {
            auto *job = static_cast<Share *>(context);
            std::string manual;
            std::string qr;
            if (status == CHIP_NO_ERROR) {
                status = ManualSetupPayloadGenerator(payload).payloadDecimalStringRepresentation(manual);
                // The QR payload wants vendor and product ids; a device that
                // did not give them leaves us with the manual code alone.
                if (status == CHIP_NO_ERROR && QRCodeSetupPayloadGenerator(payload).payloadBase38Representation(qr) != CHIP_NO_ERROR)
                    qr.clear();
            }
            auto finish = std::move(job->done);
            job->self->post([job] { delete job; });
            if (finish)
                finish(manual, qr, status);
        }
    };

    void share(std::uint64_t nodeId, std::uint16_t timeoutSeconds,
               std::function<void(const std::string &, const std::string &, CHIP_ERROR)> done)
    {
        auto *job = new Share();
        job->self = this;
        job->nodeId = nodeId;
        job->done = std::move(done);
        job->opener = std::make_unique<CommissioningWindowOpener>(commissioner.get());

        std::uint16_t discriminator = 0;
        (void)Crypto::DRBG_get_bytes(reinterpret_cast<std::uint8_t *>(&discriminator), sizeof(discriminator));
        discriminator &= 0x0FFF;

        char text[96];
        std::snprintf(text, sizeof(text), "node 0x%016llx: opening a commissioning window for %u s",
                      static_cast<unsigned long long>(nodeId), static_cast<unsigned>(timeoutSeconds));
        log(LogLevel::Info, text);

        SetupPayload payload;
        const CHIP_ERROR err = job->opener->OpenCommissioningWindow(CommissioningWindowPasscodeParams()
                                                                        .SetNodeId(nodeId)
                                                                        .SetTimeout(timeoutSeconds)
                                                                        .SetIteration(kSpake2pIterations)
                                                                        .SetDiscriminator(discriminator)
                                                                        .SetReadVIDPIDAttributes(true)
                                                                        .SetCallback(&job->callback),
                                                                    payload);
        if (err != CHIP_NO_ERROR) {
            std::unique_ptr<Share> owned(job);
            if (owned->done)
                owned->done({}, {}, err);
        }
    }

    // ---- removal ------------------------------------------------------

    struct Removal {
        Impl *self = nullptr;
        std::uint64_t nodeId = 0;
        std::function<void(CHIP_ERROR)> done;
        std::unique_ptr<CurrentFabricRemover> remover;
        Callback::Callback<OnCurrentFabricRemove> callback;

        Removal() : callback(&Removal::onRemoved, this) {}

        static void onRemoved(void *context, NodeId, CHIP_ERROR status)
        {
            auto *job = static_cast<Removal *>(context);
            job->self->forget(job->nodeId);
            auto finish = std::move(job->done);
            // The remover is still on the stack above us; free it next turn.
            job->self->post([job] { delete job; });
            if (finish)
                finish(status);
        }
    };

    // Drops what the stack holds for the node and takes it out of the registry.
    void forget(std::uint64_t nodeId)
    {
        subscriptions.erase(nodeId);
        if (commissioner)
            commissioner->SessionMgr()->ExpireAllSessions(ScopedNodeId(nodeId, commissioner->GetFabricIndex()));
        forgetNode(nodeId);
        char text[80];
        std::snprintf(text, sizeof(text), "node 0x%016llx forgotten", static_cast<unsigned long long>(nodeId));
        log(LogLevel::Info, text);
    }

    void remove(std::uint64_t nodeId, std::function<void(CHIP_ERROR)> done)
    {
        auto *job = new Removal();
        job->self = this;
        job->nodeId = nodeId;
        job->done = std::move(done);
        job->remover = std::make_unique<CurrentFabricRemover>(commissioner.get());
        const CHIP_ERROR err = job->remover->RemoveCurrentFabric(nodeId, &job->callback);
        if (err != CHIP_NO_ERROR) {
            std::unique_ptr<Removal> owned(job);
            forget(nodeId);
            if (owned->done)
                owned->done(err);
        }
    }

    // ---- commissioning ------------------------------------------------

    void commission(const std::string &setupCode, std::vector<std::uint8_t> threadDataset,
                    std::function<void(std::uint64_t, CHIP_ERROR)> done)
    {
        if (commissioning) {
            // A new code supersedes an attempt still waiting for its device.
            log(LogLevel::Info, "commissioning: cancelling the attempt in progress");
            (void)commissioner->StopPairing(commissioning->nodeId);
            finishCommissioning(CHIP_ERROR_CANCELLED);
        }
        auto job = std::make_unique<Commissioning>();
        job->nodeId = allocateNodeId();
        job->done = std::move(done);
        commissioning = std::move(job);

        commissioningParams = CommissioningParameters();
        commissioningParams.SetDeviceAttestationDelegate(this);
        commissioningDataset = std::move(threadDataset);
        if (!commissioningDataset.empty())
            commissioningParams.SetThreadOperationalDataset(
                ByteSpan(commissioningDataset.data(), commissioningDataset.size()));

        char text[128];
        std::snprintf(text, sizeof(text), "commissioning node 0x%016llx over the network%s",
                      static_cast<unsigned long long>(commissioning->nodeId),
                      commissioningDataset.empty() ? "" : ", with the Thread dataset");
        log(LogLevel::Info, text);

        const CHIP_ERROR err = commissioner->PairDevice(commissioning->nodeId, setupCode.c_str(), commissioningParams,
                                                        DiscoveryType::kDiscoveryNetworkOnly);
        if (err != CHIP_NO_ERROR) {
            finishCommissioning(err);
            return;
        }
        (void)DeviceLayer::SystemLayer().StartTimer(System::Clock::Seconds32(kCommissioningDeadlineSeconds),
                                                    &Impl::onCommissioningDeadline, this);
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

void Controller::commission(const std::string &setupCode, std::vector<std::uint8_t> threadDataset, std::function<void(std::uint64_t, CHIP_ERROR)> done)
{
    m_impl->post([this, setupCode, threadDataset = std::move(threadDataset), done = std::move(done)]() mutable {
        m_impl->commission(setupCode, std::move(threadDataset), [this, done = std::move(done)](std::uint64_t nodeId, CHIP_ERROR err) {
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

void Controller::subscribe(std::uint64_t nodeId)
{
    m_impl->post([this, nodeId] { m_impl->subscribe(nodeId); });
}

void Controller::setLevel(std::uint64_t nodeId, std::uint16_t endpoint, std::uint8_t level, std::function<void(CHIP_ERROR)> done)
{
    m_impl->post([this, nodeId, endpoint, level, done = std::move(done)]() mutable {
        m_impl->setLevel(nodeId, endpoint, level, std::move(done));
    });
}

void Controller::setColorTemperature(std::uint64_t nodeId, std::uint16_t endpoint, std::uint16_t mireds,
                                     std::function<void(CHIP_ERROR)> done)
{
    Impl *impl = m_impl.get();
    impl->post([impl, nodeId, endpoint, mireds, done = std::move(done)]() mutable {
        impl->setColorTemperature(nodeId, endpoint, mireds, std::move(done));
    });
}

void Controller::setHueSaturation(std::uint64_t nodeId, std::uint16_t endpoint, std::uint8_t hue, std::uint8_t saturation,
                                  std::function<void(CHIP_ERROR)> done)
{
    Impl *impl = m_impl.get();
    impl->post([impl, nodeId, endpoint, hue, saturation, done = std::move(done)]() mutable {
        impl->setHueSaturation(nodeId, endpoint, hue, saturation, std::move(done));
    });
}

std::string Controller::compressedFabricId() const
{
    return m_impl->compressedFabricIdHex;
}

void Controller::setNodeLabel(std::uint64_t nodeId, const std::string &label, std::function<void(CHIP_ERROR)> done)
{
    Impl *impl = m_impl.get();
    impl->post([impl, nodeId, label, done = std::move(done)]() mutable {
        impl->setNodeLabel(nodeId, label, std::move(done));
    });
}

void Controller::setDeviceName(const std::string &deviceId, const std::string &name)
{
    m_impl->setDeviceName(deviceId, name);
}

std::string Controller::deviceName(const std::string &deviceId) const
{
    return m_impl->deviceName(deviceId);
}

void Controller::setFabricLabel(std::uint64_t nodeId, const std::string &label, std::function<void(CHIP_ERROR)> done)
{
    Impl *impl = m_impl.get();
    impl->post([impl, nodeId, label, done = std::move(done)]() mutable {
        impl->setFabricLabel(nodeId, label, std::move(done));
    });
}

void Controller::share(std::uint64_t nodeId, std::uint16_t timeoutSeconds,
                       std::function<void(const std::string &, const std::string &, CHIP_ERROR)> done)
{
    Impl *impl = m_impl.get();
    impl->post([impl, nodeId, timeoutSeconds, done = std::move(done)]() mutable {
        impl->share(nodeId, timeoutSeconds, std::move(done));
    });
}

void Controller::remove(std::uint64_t nodeId, std::function<void(CHIP_ERROR)> done)
{
    Impl *impl = m_impl.get();
    impl->post([impl, nodeId, done = std::move(done)]() mutable { impl->remove(nodeId, std::move(done)); });
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
