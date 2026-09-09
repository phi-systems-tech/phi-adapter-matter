# Bring-up runbook: commissioning a fresh Matter-over-Thread device

Self-contained state + plan so a fresh session on another machine can pick this
up without prior context. Written 2026-09-09.

## Goal

Commission a **factory-fresh Matter-over-Thread lamp onto phi's own fabric** (not
Apple/Google Home). The lamp in hand is new and is to be brought up via phi's own
controller.

## Current state (2026-09-09)

- **This adapter is a Matter controller** with its own fabric (own root of trust,
  IPK, controller node id under `<tenant data>/matter/<instance>/`). It does
  on-network commissioning, and now BLE commissioning too — see next point.
- **BLE commissioning is WIRED but DORMANT and opt-in** (commit `d0f0a20`). It is
  OFF unless the `bleAdapter` config field is set to a Bluetooth adapter index; the
  build is behaviour-neutral without it and links clean. The CHIP SDK
  (`phi-chip` / `libchip.a`) is already built with BLE
  (`chip_config_network_layer_ble` default true), so no CHIP rebuild is needed.
- **Thread side is READY:** `phi-otbr-runtime` runs an OpenThread border router on
  taifun's 802.15.4 dongle; the Thread network **"phi"** is live. This adapter reads
  the OTBR's active operational dataset and hands it to joining devices
  (commit `5faf665`).
- **taifun (the box, a VirtualBox VM) has NO Bluetooth hardware.** This is the one
  missing piece for the real end-to-end test — not the device.

## Why BLE is mandatory for a fresh Thread device

A factory-fresh Thread device is on no IP network yet. Its only rendezvous channel
for commissioning is **BLE**: the commissioner connects over BLE, does PASE with the
printed passcode, sends the Thread operational dataset + fabric credentials; the
device then joins the Thread mesh and becomes reachable via mDNS on the mesh. There
is no BLE-less path for a factory-fresh Thread device — this is Matter spec, not an
adapter limitation. (Ethernet/Wi-Fi Matter devices differ; this lamp is Thread.)

## The `bleAdapter` config field

`bleAdapter` (Int, range -1..15, default **-1**). `-1` disables BLE (on-network only);
set it to the hci index (`0` = hci0) to enable BLE commissioning. Defined in the
adapter's config schema and meta in `src/main.cpp`, read in `applyConfig`, passed to
the controller `Options.bleAdapter`. At bring-up, when `>= 0`, the controller calls
`DeviceLayer::Internal::BLEMgrImpl().ConfigureBle(idx, /*aIsCentral=*/true)` (Linux
defaults to peripheral; a commissioner must be central) and `commission()` then uses
`DiscoveryType::kAll` (BLE + on-network) instead of `kDiscoveryNetworkOnly`.

## Path A — real end-to-end test (needs a USB BT dongle on taifun)

The full, real test: lamp ends up on **phi's own fabric**, exercising the whole stack
including the dormant BLE path.

1. Get a USB BT dongle (Realtek RTL8761B, e.g. TP-Link UB500). Pass it into the VM via
   **VirtualBox USB passthrough** (VBox emulates no BT controller; the host OS is
   irrelevant).
2. On taifun run `bluetoothd` **with `--experimental` (`-E`)**, preferably `-P battery`.
   Confirm with `bluetoothctl list` that `hciN` appears.
3. The sidecar process needs **`CAP_NET_ADMIN` (+`CAP_NET_RAW`) or root** and D-Bus
   access to `org.bluez`. BlueZ **>= 5.63** (5.66 known-good, avoid 5.79).
4. Deploy the adapter, set the `bleAdapter` field to the hci index (`0`), and
   `phi-cli adapter reload <name>` (reload, not restart).
5. Trigger the adapter's `commission` action with the lamp's **11-digit manual setup
   code** (or QR payload). The adapter discovers over BLE (`kAll`), does PASE, pushes
   the OTBR Thread dataset + fabric creds; the lamp joins Thread "phi" and surfaces as
   phi devices/channels.

Note: the 802.15.4 (OTBR) radio and the BT (HCI) radio are separate hardware, so OTBR
and the BLE commissioner do not contend.

## Path B — interim validation on a BLE-capable machine (no box BT)

De-risk while the dongle isn't here, using the reference commissioner `chip-tool` on
any Linux/Mac that has Bluetooth. This validates the **lamp, its QR/code, the Thread
join into our "phi" network, and cluster control** — everything EXCEPT this adapter's
own BLE path.

1. Build/obtain `chip-tool` from `connectedhomeip` (match the pinned SDK version —
   `phi-chip` pins **v1.5.1.0**). Run it on the BLE machine, with local BlueZ started
   `--experimental`.
2. Get the active Thread operational dataset (hex TLV) from taifun's OTBR:
   `ot-ctl dataset active -x` (via the OTBR console socket that `phi-otbr-runtime`
   exposes). Copy the hex string.
3. Commission over BLE onto chip-tool's own (throwaway) test fabric + our Thread net:
   `chip-tool pairing code-thread <node-id> hex:<dataset-hex> <setup-code> [--ble-adapter <n>]`
   e.g. `chip-tool pairing code-thread 1 hex:0e080000... 34970112332 --ble-adapter 0`
4. Confirm control:
   `chip-tool onoff toggle 1 1` / `chip-tool levelcontrol move-to-level 128 0 0 0 1 1`.

Caveat: the lamp ends up on chip-tool's **test fabric, NOT phi's**. Fine for a bring-up
sanity check; factory-reset the lamp and re-commission via Path A afterwards (or open a
commissioning window and multi-admin it later).

## The lamp

Factory-fresh Matter-over-Thread lamp. Needs its printed **QR + 11-digit setup code**.
Do NOT commission it into Apple/Google Home first — that consumes the passcode and puts
it on their fabric; it would then need a factory reset before phi can take it.

## What is committed here

- `d0f0a20` — BLE commissioning wired (dormant, opt-in): `src/controller.{h,cpp}`,
  `src/main.cpp` (the `bleAdapter` field), `CMakeLists.txt` (adds
  `CHIP_DEVICE_CONFIG_ENABLE_CHIPOBLE=1 CONFIG_NETWORK_LAYER_BLE=1` on the adapter
  target, because `phi-chip`'s export keeps `CHIPOBLE` private to the SDK, so the
  adapter must declare its own matching BLE view).
- `5faf665` — reads the border router's Thread network and hands it to joining devices.

## Decision

Lamp is fresh → commission via **phi's own way (Path A)** once a BT dongle is on
taifun. **Path B** is the interim de-risk on a separate BLE machine (needs the repos
checked out there first). Blocker for Path A is purely the USB Bluetooth dongle.
