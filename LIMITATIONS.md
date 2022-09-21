# Security limitations

This document's goal is to provide a short discussion on what security
properties access to /dev/sev-guest has, specifically in a Cloud setting.

## Initial assumptions

For claims in this document, we assume that the VM firmware is vendored and
signed by the vendor, or not signed at all. This will be the common use case.

If a virtual machine monitor gives you access to provide your own launch image
and signed IDBlock, then you have full control and responsibility over what that
image does, and how careful it is to give workloads access to the SEV
device. Since this library is for wrapping the Linux driver /dev/sev-guest which
will be booted from a UEFI firmware, further discussion of other uses of SEV-SNP
are out of scope.

## Implications of a vendored firmware

Your Cloud service provider (CSP) may launch SEV-SNP VMs with their own build of
UEFI firmware. This build and its signature in IDBlock are probably widely
deployed across the CSP's fleet.  Because the firmware and IDBlock are the same
everywhere, the measurement in the attestation report will be the same
everywhere. The IDBlock, if provided, may also be the same everywhere.

The security of an attestation measurement or a derived key are proportional to
the specificity of the initially measured image. If the initial image and its
IDBlock is available to everyone and can run any workload, then keys bound to
their measurement are known to everyone. An IDBlock signed by a different key
will lead to different keys, but the IDBlock and ID Auth are also not secret
in the SEV-SNP threat model. The measured image's behavior in granting
authorization is what is important.

At the moment, the basis for most VM firmware, Open Virtual Machine Firmware
(OVMF), does not have the behavior to lock in such a specific measurement and
authorization semantics in a way that is reflected in the SEV-SNP attestation
report. Measured boot integrity is dynamic post-launch via the TPM 2.0
specification, which for VMs is virtualized in software and not secret within
the SEV-SNP threat model.

Supposing we did have a boot stack that accounted for workload and its
configuration in the SEV-SNP attestation report, software updates change the
measurement and thus change the derived keys. In a self-updating VM, you'd need
custom software to manage the implications of changing derived keys.

## MSG_KEY_REQ, or GetDerivedKey

Keys are derived from the launch information discussed above and the specific
machine's SEV-SNP key called the Versioned Chip Endorsement Key (VCEK). When you
do not have full control over the machine that derives the key, and your launch
image isn't fully linked to the workload you trust to have access to the key,
you should not set `UseVCEK` to true.

With `UseVCEK` set to false, you must be using an image that supports a migration
agent (MA). The MA will register a root key that migrates with the image, called
the VMRK. The security of this VMRK is entirely up to the MA's logic. If the
key is meant to persist across full shutdown and restart, then you have to solve
a hard problem: sealing that key to persist in a way that only the authorized
workload should later have access to. That is the same problem that exists for
VCEK.

If you're okay with keys that migrate but aren't otherwise recoverable, then
VMRK key-based derivation should meet your needs. To many, that possibility of
unrecoverable data loss is too risky to choose this option either.

Because of the danger in both root key selections, we do not recommend using
this command unless you have full ownership of and secure physical access to the
machine that will run it, and trust all parties that run software on that
machine.
