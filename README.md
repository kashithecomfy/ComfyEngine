# ComfyEngine

Qt-based memory scanner / watchlist playground inspired by Cheat Engine but works nativly on Linux and tuned for my workflow:
clean docks, pointer graphs, quick patching, and zero fear of losing context when you bounce between
scanner, scripts, and notes.


## What you get

- **Scanner** – Exact/Unknown/Changed/Range/AoB, optional alignment, fast scan, skip masked pages.
- **Results/Watchlist** – Per-row scripts, pointer flagging, freeze + auto-enforce, spike coloring,
  save/load tables, tracking dock for diffing snapshots.
- **Pointer + Memory tools** – Pointer graph visualization, memory viewer, hex patch widget, Auto
  Assembler templates, and auto-generated `patch/restore` scripts.
- **Quality-of-life** – Notes dock, script editor, navigator sidebar, settings page with launch
  options, detach confirmation, refresh cadence, spark duration, etc.


<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/506a020f-d516-4bee-9215-c830cdac00cc" />


(The colors depend on your theme. The whole UI is customizable.)

## Build

Requirements: Qt 6 (Widgets), Capstone, CMake ≥ 3.16, C++17 compiler, Ninja/Make.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
# optional
cmake --install build --prefix /usr/local
```

Executable lives in `./build/src/comfyengine`. Helper utilities (`test_watch`, `ce_watch`) stay in
the repo root.

## Run-through

1. Launch the app, click **Select process…**, pick your target.
2. Enter a value in the Memory Scan panel, hit **First Scan**, then **Next Scan** to narrow things
   down. Switch modes if you’re hunting by ranges/AoB.
3. Double-click a result to throw it into the watchlist. Right-click for patching, pointer tracing,
   or “Track changes”.
4. Use the toolbar buttons for Auto Assembler, Memory Viewer, Pointer Scanner, and stuff.
5. Navigator dock on the left switches between Scanner, Memory, Scripts, Pointer Graph, Tools,
   Settings, and stuff.

Settings persist via `QSettings` so whatever layout/refresh cadence you prefer sticks next boot.

## Tests

```bash
ctest --test-dir build --output-on-failure
./build/test_watch
```

Register new suites via `add_test` in the relevant `CMakeLists.txt`.

## Want to help keep things comfy?

- File issues / PRs: [github.com/kashithecomfy/ComfyEngine](https://github.com/kashithecomfy/ComfyEngine)
- Buy me caffeine: [buymeacoffee.com/comfykashi](https://buymeacoffee.com/comfykashi)

This is my first public project, hopefully will do more!
Have fun breaking apps responsibly.
