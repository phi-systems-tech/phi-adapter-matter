# phi-adapter-matter

The southbound Matter controller for phi, built on `connectedhomeip`.

## What is here now

chip-tool, and nothing else. The SDK is fetched at the tag in
`debian/CHIP_VERSION` and built for this architecture inside the package build.
No adapter code exists yet, on purpose: the decision to build on the CSA's C++
reference implementation rather than on matter.js is recorded in phi-core's
roadmap under M6, and the bill attached to it is the build - GN plus Pigweed,
gigabytes of submodules, not in Debian. A stack one cannot package is a stack
one does not have, so the build is the first milestone and the adapter waits
for it.

What the first successful build answers:

- whether Pigweed's bootstrap finds gn, ninja, its Python and zap on CIPD for
  arm64, in a chroot, with a HOME that is not anybody's;
- how long it takes on a Pi-class machine and on the sbuild host;
- how big the result is.

The last two are written into the package as
`/usr/share/doc/phi-adapter-matter/CHIP-BUILD-INFO`, beside the tag and the
commit, so the next build has a number to compare against.

## What comes next

The adapter sidecar as a second GN target beside chip-tool, inside the SDK's
own build rather than against an exported `-dev` package: CHIP has no install
target and its headers include generated code, so packaging it as a library
would be a maintenance job with no end. The sidecar links the prebuilt
`phi-adapter-sdk` from its `-dev` package, the way every other adapter does,
and the package stops being "chip-tool" and becomes what its name says.

chip-tool stays in the package afterwards as the diagnostic it is: the
commissioning and cluster commands upstream tests with, on the same SDK build
the adapter runs on.

## Building

```
dpkg-buildpackage -us -uc -b
```

The build needs the network, like phi-nodejs and phi-z2m-runtime do: the
source comes from upstream's tag, the toolchain from CIPD. Everything lands
under `debian/upstream/` - checkout, Pigweed environment, CIPD cache, a HOME
of its own - and nothing outside it.

`debian/rules clean` keeps the checkout, because throwing away several
gigabytes of upstream source would turn every rebuild into a fresh download.
`PHI_DROP_CHIP_SOURCE=1 debian/rules clean` removes it too.

Disk: reserve 10 GB for the checkout and the build together before the first
attempt, and more for the dbgsym package `dh_strip` splits off an unstripped
chip-tool into.

## Bumping the SDK

Change `debian/CHIP_VERSION` and the `+chip...` part of the package version in
`debian/changelog` together. The tag is in the version so that what a machine
runs is visible in `apt show`, not only inside the package.

## Not yet decided, written down so it is not decided by default

- mDNS: chip-tool builds with the SDK's minimal resolver. The adapter will run
  on a box that already has Avahi, and `chip_mdns="platform"` is the switch;
  which one the adapter uses is a decision for when there is an adapter.
- BLE: on by default in the Linux build, over BlueZ. Thread devices commission
  over BLE first, so the adapter will want it - and BLE is a host resource the
  host layer has not modelled yet. See the roadmap.

## License

See `LICENSE`. chip-tool is upstream's code under Apache-2.0; see
`debian/copyright`.
