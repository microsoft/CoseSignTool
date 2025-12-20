# cosesign1-hello-world

A tiny C++20 console app showing how to consume the native verifier packages.

See `native/docs/hello-world.md` for a guided walkthrough.

## Build (vcpkg toolchain + overlay ports)

From the repo root:

```powershell
$env:VCPKG_ROOT = "C:\vcpkg"  # adjust if needed

cmake -S native/examples/cosesign1-hello-world -B native/examples/cosesign1-hello-world/out/build \
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" \
  -DVCPKG_OVERLAY_PORTS="${PWD}\native\vcpkg-ports"

cmake --build native/examples/cosesign1-hello-world/out/build --config Release
```

## Run

```powershell
native/examples/cosesign1-hello-world/out/build/Release/cosesign1_hello_world.exe
```
