# vSGX: Virtualizing SGX Enclaves on AMD SEV

## About the Project

This is a research project aims to enable binary compatibility execution of Intel SGX enclaves on AMD SEV machines. The paper is accepted to 2022 IEEE Symposium on Security and Privacy. You can download the paper [here](https://www.computer.org/csdl/proceedings-article/sp/2022/131600a687/1A4Q3q3W28E).

All implementations except for existing code bases (Linux, Intel SGX SDK, etc.) were written and debugged by NSKernel.  

## License

This project is opensourced under GPLv2. See [`LICENSE`](LICENSE).

Copyright (C) 2022 [NSKernel](https://u.osu.edu/zhao-3289/) and [OSU SecLab](https://seclab.engineering.osu.edu).

Other components included in this repository are also licensed under GPLv2.
+ Linux SGX Driver (See [`linux-sgx-driver/License.txt`](linux-sgx-driver/License.txt))
+ `arch/x86/kvm/cpuid.c` and `arch/x86/kvm/Makefile` from Linux (See [`kvm/LICENSE.txt`](kvm/LICENSE.txt))

## Quick Start Guide

Disclaimer: vSGX IS NOT BUG FREE AND [THERE IS NO WARRANTY FOR THE CODE](LICENSE). KERNEL CODE MODIFICATIONS IN IT MAY CAUSE KERNEL PANICS AND/OR DESTRUCTIVE CONSEQUENCES. DO NOT TEST THE CODE ON ANY MACHINE THAT YOU ARE NOT WILLING TO WIPE.

This project once was called 'EmuSGX'. Some of the naming in the code is still carrying this name.

The following assumes a Ubuntu environment. Suppose you are at `~/`.

### Step 0: Check if your machine meets the requirement and if you are ready

+ Machine has an SEV processor
+ Machine has SEV enabled in the UEFI
+ You know how to build and install Linux kernel
+ You know how to build and install Linux SGX SDK and build SGX software
+ You have read the paper

This is a relatively complicated system with multiple components down from kernels, kernel modules up to SDK and environments. I recommend you to have proper experiences on kernel coding and SGX SDK to minimize your frustration in your adventure.

### Step 1: Clone this project

```
git clone https://github.com/OSUSecLab/vSGX.git
```

### Step 2: Build the hypervisor infrustructure

Clone the AMD SEV project

```
git clone https://github.com/AMDESE/AMDSEV.git
```

Checkout the SEV-ES branch (Even if you just have SEV. SEV-ES works on both SEV and SEV-ES)

```
git checkout sev-es
```

The reference commit we tested is  `222e2942a10e0174b5ef90439785641a956c45ad`.

Follow the `README.md` to build the SEV environment. Install everything built EXCEPT FOR THE KERNEL. 

Copy the 4 files under the `vSGX/kvm` folder to overwrite the corresponding ones in `AMDSEV/build/linux/arch/x86/kvm`. 

```
cp vSGX/kvm/* AMDSEV/build/linux/arch/x86/kvm
```

Build the kernel again manually by

```
cd AMDSEV/build/linux
make -j $(getconf _NPROCESSORS_ONLN) LOCALVERSION='-vsgx' bindeb-pkg
```

Install the built kernel `.deb` packages. You can now launch your own VMs on SEV-ES using QEMU. Create two VMs: the AVM and the EVM, both using stock Ubuntu with OVMF according to the `README.md`. (Note that you do not need a GUI to run vSGX)

### Step 3: Prepare the EVM

Clone the 5.10.20 version of 5.10.y branch of Linux Stable Tree

```
cd ~
git clone -b "v5.10.20" --depth 1 --single-branch https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
```

Apply the EVM patch

```
git am ~/vSGX/evm-kernel.patch
```

Create a build folder and use the given configuration `evm-config` to build the EVM kernel

```
cd ~
mkdir evm-kernel-obj
cd linux
make O=../evm-kernel-obj/ defconfig
cp ../vSGX/evm-config ../evm-kernel-obj/.config
make O=../evm-kernel-obj/ oldconfig
```

Build the EVM kernel

```
make O=../evm-kernel-obj/ -j $(getconf _NPROCESSORS_ONLN) LOCALVERSION='-vsgx-evm' bindeb-pkg
```

You can now launch the EVM you just created in Step 2 and install the kernels. 

Copy `kvm/enclave-manager` into the EVM. Build the enclave manager by

```
cd enclave-manager
gcc -pthread asm_helpers.c manager.c
```

### Step 4: Prepare the AVM

We suggest you to use a clean and plain Linux 5.10.20 on AVM. The kernel module might not work with a different version. To build a clean and plain Linux 5.10.20, checkout back to `linux-5.10.y` branch, build and install. You should have `CONFIG_KALLSYMS` and `CONFIG_KALLSYMS_ALL` enabled.

Copy `vSGX/emusgx-guest-module`, `vSGX/sdk.patch` and `vSGX/linux-sgx-driver` into the AVM. (See why and how the driver is modified in [`COMPATIBILITY.md`](COMPATIBILITY.md))

Now in AVM, build the Linux SGX Driver we provided

```
cd linux-sgx-driver
make
```

Clone the Linux SGX SDK

```
cd ~
git clone https://github.com/intel/linux-sgx.git
```

Checkout the commit `9671c99941814c57be575cbfebc9fe64a05533a4` (We do not guarantee that there is no conflict of our code with other commits) and create a new branch out of it

```
git checkout -b vsgx
```

Apply our patch (See why and how the SDK is modified in [`COMPATIBILITY.md`](COMPATIBILITY.md))

```
git am ~/sdk.patch
```

Build the SDK and PSW according to the `README.md`, install it.

### Step 5: Run the system

In AVM, install both the `emusgx-guest-module` and the provided `linux-sgx-driver`

```
cd ~/emusgx-guest-module
make install
<Type your password>
cd ~/linux-sgx-driver
sudo insmod isgx.ko
```

To ensure everything works, you can type `dmesg` and you should see this

```
[   xx.xxxxxx] EmuSGX: Initializing guest OS module...
[   xx.xxxxxx] vSGX: Fucking kallsyms...
[   xx.xxxxxx] vSGX: kallsyms_lookup_name@0xFFFFFFFFXXXXXXXX
[   xx.xxxxxx] EmuSGX: Hooking IDT...
[   xx.xxxxxx] EmuSGX: IDT hooked. EmuSGX is now running
[   xx.xxxxxx] EmuSGX: Initializating shared page
[   xx.xxxxxx] EmuSGX: Share page initialization is done
[   xx.xxxxxx] vSGX: Worker threads successfully created
[   xx.xxxxxx] not_intel_vsgx: hey! I'm running on AMD??
[   xx.xxxxxx] not_intel_vsgx: not even having SGX??
[   xx.xxxxxx] not_intel_vsgx: you won't believe what I'm running on
[   xx.xxxxxx] intel_sgx: Not Intel SGX Driver v2.11.0
[   xx.xxxxxx] not-intel-sgx: EPC bank 0x80000000-0x95000000
[   xx.xxxxxx] not-intel-sgx: bank 0 mapped to va @ 0xFFFFXXXXXXXXXXXX
[   xx.xxxxxx] not_intel_sgx: now registering /dev/isgx
[   xx.xxxxxx] not_intel_sgx: registered
```

To see all the logs in AVM in real time, type `sudo dmesg -n 8`. The AVM side is now ready.

Now on EVM side, run the enclave manager by

```
cd enclave-manager
./a.out
```

You should see

```
vSGX: Switchless worker is on
vSGX: Dispatcher worker is on
```

To check the EVM is registered to the AVM, a `dmesg` on AVM side should show

```
[   xx.xxxxxx] EmuSGX: Registered VM at 0 with ID XXXXXXX
```

Now build a sample code from the Intel SGX SDK. Remember to source the environment as instructed by the SDK installer.

```
source ${sgx-sdk-install-path}/environment
cd linux-sgx/SampleCode/SampleEnclave
make
```

Run the code by typing

```
./app
```

The app should just work.

### Step 6: Clean up

A launched EVM must be discarded. Just kill it. The AVM can be safely shutdown.

## More to Come...

Graphene-SGX requires some more modifications to overcome the `GenuineIntel` check and `CPUID` related problems. We will provide a patch to it later so you can try running it yourself.

## TODO List

+ `EINIT`'s signature check is bypassed right now because I tried the kernel cryptographic APIs but failed to make it work. However this is an engineering effort and a person who is familiar with the APIs can help. Your patch is welcome.
+ Syscall interface in EVM is left open for debug purposes. You can disable syscalls by adding
```
if (current->is_enclave_thread) {
	panic("vSGX: Enclave accessed syscalls. Abort.\n");
	// or expand the AEX for UD and drop an AEX here
}
```
+ Minimisation of the EVM kernel. In fact, everything except for thread and memory management can be trimmed. The enclave does not rely on any conventional system service.
+ This is an implementation to demonstrate the feasibilty and to illustrate the performance of the paper. There might be some bugs remain in the system.