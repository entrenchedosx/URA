$ErrorActionPreference='Stop'
$root=(Resolve-Path "$PSScriptRoot/..").Path
$llvm=Split-Path (Get-Command clang.exe).Source
& "$llvm/clang.exe" --target=i686-pc-windows-msvc -c "$root/tests/fixtures/patch-x86.s" -o "$root/target/patch-x86-pe.obj"
if ($LASTEXITCODE -ne 0) {throw 'PE fixture assembly failed'}
& "$llvm/lld-link.exe" /machine:x86 /entry:patch_entry /subsystem:console /nodefaultlib /safeseh:no /timestamp:0 "/out:$root/tests/fixtures/patch32.exe" "$root/target/patch-x86-pe.obj"
if ($LASTEXITCODE -ne 0) {throw 'PE fixture link failed'}
& "$llvm/clang.exe" --target=i386-unknown-linux-gnu -c "$root/tests/fixtures/patch-x86.s" -o "$root/target/patch-x86-elf.o"
if ($LASTEXITCODE -ne 0) {throw 'ELF fixture assembly failed'}
& "$llvm/ld.lld.exe" -m elf_i386 -e _patch_entry --build-id=none -o "$root/tests/fixtures/patch32.elf" "$root/target/patch-x86-elf.o"
if ($LASTEXITCODE -ne 0) {throw 'ELF fixture link failed'}
Get-FileHash "$root/tests/fixtures/patch32.exe","$root/tests/fixtures/patch32.elf"
