#ifndef EMUSGX_CPUID_H
#define EMUSGX_CPUID_H

#define KVM_CPUID_EMUSGX_GUEST_SEND_PAGE 	0x40000005
#define KVM_CPUID_EMUSGX_GUEST_ACK_PAGE  	0x40000006
#define KVM_CPUID_EMUSGX_GUEST_SHARE_PAGE	0x40000007
#define KVM_CPUID_EMUSGX_GUEST_UNSHARE_PAGE	0x40000008

#define KVM_CPUID_EMUSGX_RUN_SENDER_KTHREADS	0x40000009
#define KVM_CPUID_EMUSGX_STOP_SENDER_KTHREADS	0x4000000A
#define KVM_CPUID_EMUSGX_CHECK_SENDER_KTHREADS	0x4000000B
#define KVM_CPUID_EMUSGX_RESET_HYPERVISOR	0x4000000C

#define KVM_CPUID_EMUSGX_GUEST_RETRIVE_PAGE	0x4000000E

#endif