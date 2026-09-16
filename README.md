# phi-adapter-matter

The southbound Matter controller for phi, built on `connectedhomeip`, the
CSA's reference implementation. One adapter for every Matter device, whether
it hangs on Thread, Wi-Fi or Ethernet.

## Shape

`phi_adapter_matter_ipc` is a phi adapter sidecar (the SDK from
`phi-adapter-sdk-dev`) that embeds a CHIP controller. One adapter instance is
one fabric: its own root of trust, IPK and controller node id, under
`<tenant data>/matter/<instance>/`. Every node commissioned into it is
described from its Descriptor cluster and its endpoints become phi devices
with the channels their clusters carry: on/off, brightness, color temperature,
color, motion, contact, temperature, humidity, illuminance, battery, and a
connectivity channel on all of them. A bridge stays visible as a gateway and
the devices behind it carry it as `parent`.

Instance actions: commission (pairing code, over the network), share (opens
an enhanced commissioning window and answers with the manual code and the
QR payload), remove, and the device card's delete. The fabric carries the
instance name as its label on every node. A rename reaches a device only
where it lands on the device itself; everything behind a bridge is marked
`fixedName`.

## Logging

Two voices, and they do not share a channel. What this adapter did is its own:
a node commissioned or forgotten, a fabric up, a subscription dropped, a node
gone unreachable - at `Info`, `Warn` or `Error`, and always sent, switch or no
switch.

CHIP's own log is the other, and it is the library talking about its attempts.
It arrives one step below the level the SDK gives it: `kLogCategory_Error` as
`Debug`, progress and detail as `Trace` - which is where chatter belongs.
A CASE session that timed out and a D-Bus call that failed because
`bluetooth.service` is masked on this box are not statements about the adapter,
and the things that do matter, the adapter says itself. So the stream is there
when the instance's "Logs" switch is on and silent when it is off; turning it
on also lets those lines past core's journal threshold.

What core says - the process starting, an instance being created, a
`config.changed` arriving - this adapter does not repeat.

## Building

The SDK is not built here. `phi-chip-dev` ships connectedhomeip as one static
library with its headers, flags and the PAA roots, and this repository is a
plain CMake project against it:

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja -C build
dpkg-buildpackage -us -uc -b
```

Seconds, no network. The package records the SDK build it linked in
`Built-Using`. chip-tool, upstream's diagnostic controller from the same SDK
build, is in `phi-chip-tools`.

The record of what the first CHIP builds taught, and the decision for CHIP
over matter.js, is in phi-core's roadmap under M6.
