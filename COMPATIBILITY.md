# Discussion on the Compatibility of vSGX

## What's not compatible

We only support the compatibility of SGX on AMD SEV platforms. You should not expect to run AVX 512 on vSGX. You should not expect `CPUID` will return `GenuineIntel`. We did not implement the `CPUID` leaves for SGX and you should not use them to check for capability of the system.

## Our modifications to SGX SDK and Driver

In Intel SGX SDK, Intel uses `CPUID` to check for SGX capabilities. We modified it to be hard-coded.

In SGX Driver, `CPUID` is also used to determine the physical address of SGX memory and memory bank information. We modified it to be hard-coded. We picked a random address because it is emulated and does not matter anyway since both the OS and the app uses virtual address.

## Can these be solved?

For unsupported instruction extension like AVX 512 you can use a similar method as vSGX to emulate them but it does not make sense to do so.

For `CPUID`, we can indeed modify the hypervisor's `CPUID` handler to return faked values, pretending to be a real Intel SGX-capable processor. However this will cause subtle effects to SEV platform recogonisation in the kernel and must be handled with care. We believe it is more of an engineering effort and circumvented it by hard-coding these info. There are only a few points of it as you can see in the patch to the SDK and the driver's `sgx_main.c`. For most apps written using Intel SGX SDK, since the problem is circumvented already in the SDK, they just work. For other apps like Graphene-SGX, they will have to remove these `CPUID` checks before running on vSGX.