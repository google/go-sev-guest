# Installation instructions

go-sev-guest is a library and set of CLI tools for interacting with the
`/dev/sev-guest` driver. There are thus a few requirements for its use.

## System requirements

This driver is only available on AMD SEV-SNP enabled virtual machines. Do
determine support, run

```shell
dmesg | grep "SEV-SNP supported"
```

Your Linux distribution may build in support for the sev-guest driver, or may
relegate it to a loadable kernel module.

Ensure the module is loaded with

```shell
modprobe sev-guest
```

If this command fails, check with your distribution for which installable
package it may be distributed in, and install that. For example, Ubuntu may
distribute `sev-guest` in `linux-modules-$(uname -r)`.

## Kernel config

When building your own Linux kernel, on top of the other configuration options
needed for SEV-SNP, you will need to have `CONFIG_VIRT_DRIVERS=y` and either
`CONFIG_SEV_GUEST=y` or `CONFIG_SEV_GUEST=m` depending on whether you want the
driver to be built in or a module.

## Device requires root permissions

Unless your image has custom initialization rules to grant broader privileges to
the sev-guest device, the Linux user that accesses `/dev/sev-guest` must have
root privileges.

To provide attestation report capabilities to a lesser-privileged user, you will
need to create a priviledged client that can act on their behalf.
