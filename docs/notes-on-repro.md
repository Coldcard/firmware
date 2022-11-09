# Notes on Reproducible Builds

The following document aims to breakdown how reproducibility is verified in the `make repro` build step.

## stm32/shared.mk

The entrypoint makefile for repro builds.

### repro

The `repro` command in `shared.mk` is the first step in the repro build process, which triggers a docker build and run process.

```makefile
repro: 
	docker build -t coldcard-build - < dockerfile.build
	(cd ..; docker run $(DOCK_RUN_ARGS) sh src/stm32/repro-build.sh $(VERSION_STRING) $(MK_NUM))
```

Below are interesting sections from the docker logs that give an idea as to what is going on in build process:

```stdout
+ mkdir /tmp/checkout
+ mount -t tmpfs tmpfs /tmp/checkout

...
```
We will pull the release from coldcard.com into the `/tmp/checkout` directory.

```
+ git clone /work/src/.git firmware

...

+ cd firmware/external
+ git submodule update --init

...

Successfully installed signit-1.0

...

+ cd ../stm32
+ cd ../releases
+ '[' -f '*-v5.0.7-mk4-coldcard.dfu' ]
+ dd 'bs=66' 'skip=1'
+ grep -F v5.0.7-mk4-coldcard.dfu signatures.txt
0+1 records in
0+1 records out
+ PUBLISHED_BIN=2022-10-05T1724-v5.0.7-mk4-coldcard.dfu
+ '[' -z 2022-10-05T1724-v5.0.7-mk4-coldcard.dfu ]
+ wget -S https://coldcard.com/downloads/2022-10-05T1724-v5.0.7-mk4-coldcard.dfu

...

'2022-10-05T1724-v5.0.7-mk4-coldcard.dfu' saved

...

+ PUBLISHED_BIN=/tmp/checkout/firmware/releases/2022-10-05T1724-v5.0.7-mk4-coldcard.dfu

...

+ make -f MK4-Makefile setup

...

+ make -f MK4-Makefile firmware-signed.bin firmware-signed.dfu production.bin dev.dfu firmware.lss firmware.elf

...

signit sign -b l-port/build-COLDCARD_MK4 -m 4 5.0.7 -o firmware-signed.bin

...

signit sign -m 4 5.0.7 -r firmware-signed.bin -k 1 -o production.bin
You don't have that key (1), so using key zero instead!
...

cd ../external/micropython/ports/stm32 && make BOARD=COLDCARD_MK4 -j 4 EXCLUDE_NGU_TESTS=1 DEBUG_BUILD=0

...

../external/micropython/tools/dfu.py -b 0x08020000:dev.bin dev.dfu
arm-none-eabi-objdump -h -S l-port/build-COLDCARD_MK4/firmware.elf > firmware.lss
cp l-port/build-COLDCARD_MK4/firmware.elf .
+ '[' /tmp/checkout/firmware/stm32 '!=' /work/src/stm32 ]
+ rsync -av --ignore-missing-args firmware-signed.bin firmware-signed.dfu production.bin dev.dfu firmware.lss firmware.elf /work/built
sending incremental file list
dev.dfu
firmware-signed.bin
firmware-signed.dfu
firmware.elf
firmware.lss
production.bin

...

+ make -f MK4-Makefile 'PUBLISHED_BIN=/tmp/checkout/firmware/releases/2022-10-05T1724-v5.0.7-mk4-coldcard.dfu' check-repro

...

Comparing against: /tmp/checkout/firmware/releases/2022-10-05T1724-v5.0.7-mk4-coldcard.dfu
test -n "/tmp/checkout/firmware/releases/2022-10-05T1724-v5.0.7-mk4-coldcard.dfu" -a -f /tmp/checkout/firmware/releases/2022-10-05T1724-v5.0.7-mk4-coldcard.dfu
rm -f -f check-fw.bin check-bootrom.bin
signit split /tmp/checkout/firmware/releases/2022-10-05T1724-v5.0.7-mk4-coldcard.dfu check-fw.bin check-bootrom.bin
start 293 for 870400 bytes: Firmware => check-fw.bin
start 870701 for 114688 bytes: Bootrom => check-bootrom.bin
signit check check-fw.bin
     magic_value: 0xcc001234
       timestamp: 2022-10-05 17:24:55 UTC
  version_string: 5.0.7
      pubkey_num: 1
 firmware_length: 870400
   install_flags: 0x0 =>
       hw_compat: 0x8 => Mk4
         best_ts: b'\x00\x00\x00\x00\x00\x00\x00\x00'
          future: 0000000000000000 ... 0000000000000000
       signature: 293948e7ce4a3555 ... 766437aa65d3e88a
sha256^2: 7f3a7c5f794ce72f68280447cddc837fa62245fdf4b795822127624f8775dca2
 ECDSA Signature: CORRECT
signit check firmware-signed.bin
     magic_value: 0xcc001234
       timestamp: 2022-10-24 13:33:16 UTC
  version_string: 5.0.7
      pubkey_num: 0
 firmware_length: 870400
   install_flags: 0x0 =>
       hw_compat: 0x8 => Mk4
         best_ts: b'\x00\x00\x00\x00\x00\x00\x00\x00'
          future: 0000000000000000 ... 0000000000000000
       signature: deb643d0a140d89e ... c544f09cd80fa65c
sha256^2: a46ddd6e599a49a573bf76054f438c9efe1ee031bfae74a00b0e7bbe76f516c3
ECDSA Signature: CORRECT
hexdump -C firmware-signed.bin | sed -e 's/^00003f[89abcdef]0 .*/(firmware signature here)/' > repro-got.txt
hexdump -C check-fw.bin | sed -e 's/^00003f[89abcdef]0 .*/(firmware signature here)/' > repro-want.txt
diff repro-got.txt repro-want.txt

SUCCESS. 

You have built a bit-for-bit identical copy of Coldcard firmware for v5.0.7
```

## check-repro

The `check-repro` section of the makefile contains the steps required to verify that the build artifacts are infact a bit-for-bit match to the release candidates.

```makefile
check-repro: TRIM_SIG = sed -e 's/^00003f[89abcdef]0 .*/(firmware signature here)/'
check-repro: firmware-signed.bin
ifeq ($(PUBLISHED_BIN),)
	@echo ""
	@echo "Need published binary for: $(VERSION_STRING)"
	@echo ""
	@echo "Copy it into ../releases"
	@echo ""
else
	@echo Comparing against: $(PUBLISHED_BIN)
	test -n "$(PUBLISHED_BIN)" -a -f $(PUBLISHED_BIN)
	$(RM) -f check-fw.bin check-bootrom.bin
	$(SIGNIT) split $(PUBLISHED_BIN) check-fw.bin check-bootrom.bin
	$(SIGNIT) check check-fw.bin
	$(SIGNIT) check firmware-signed.bin
	hexdump -C firmware-signed.bin | $(TRIM_SIG) > repro-got.txt
	hexdump -C check-fw.bin | $(TRIM_SIG) > repro-want.txt
	diff repro-got.txt repro-want.txt
	@echo ""
	@echo "SUCCESS. "
	@echo ""
	@echo "You have built a bit-for-bit identical copy of Coldcard firmware for v$(VERSION_STRING)"
endif
```

To summarize `check-repro`:

- At the final `check-repro` step, we have a locally built `firmware-signed.bin` and we want to check that it matches the binary release provided by Coinkite.

- This step verifies the signature of the binary is valid, using either the Coinkite key factory key or the "debug" key zero which is public.

- An identical checksum match will not be possible as is, since there is signature data embedded into into the binary, which must be removed.

- The specific release of the version that is being built is fetched, and placed it under /tmp/checkout/firmware/releases/*.dfu

- `split` (cli/signit.py: Line 153-175) is run against the release `*.dfu` resulting in a `check-fw.bin` and `check-bootrom.bin`. "This splits the DFU file into the two parts it contains: the main firmware (COLDCARD application) and the boot loader code."

- `check` (cli/signit.py: Line 176-241) is run against each the release `check-fw.bin` and our built `firmware-signed.bin`.

- a hexdump is taken of each the release `check-fw.bin` and our built `firmware-signed.bin` piped through $TRIM_SIG which removes 64 bytes of signature data and subsitutes it with a common string.

- Finally the diff of the two hexdumps are compared to prove reproducibility.
