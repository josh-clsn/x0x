//! Survivor re-key A8 (review I-2): whether this Linux or Android system
//! runs under a hypervisor. A guest whose VM is paused, or whose host
//! sleeps (WSL2 under a sleeping Windows included), never suspends itself:
//! `CLOCK_BOOTTIME` and `CLOCK_MONOTONIC` stop together, so the suspend pair
//! cannot see the pause. Such a system is TTL only.
//!
//! Every marker is a plain file read or an environment variable. Any one
//! marker is enough, and an unreadable `/proc/cpuinfo` counts as one: a
//! false "virtual machine" costs connected mode, a false "bare metal" can
//! leak.

/// DMI strings that name a hypervisor or a cloud VM, lowercase.
const DMI_MARKERS: &[&str] = &[
    "qemu",
    "kvm",
    "vmware",
    "virtualbox",
    "innotek",
    "xen",
    "bochs",
    "parallels",
    "bhyve",
    "hyper-v",
    "virtual machine",
    "virtualization",
    "cloud hypervisor",
    "amazon ec2",
    "google compute engine",
    "openstack",
    "digitalocean",
    "hetzner",
    "nutanix",
    "acrn",
];

const DMI_FILES: &[&str] = &[
    "/sys/class/dmi/id/sys_vendor",
    "/sys/class/dmi/id/product_name",
    "/sys/class/dmi/id/product_version",
    "/sys/class/dmi/id/board_vendor",
    "/sys/class/dmi/id/bios_vendor",
    "/sys/class/dmi/id/chassis_vendor",
];

/// Device-tree and board strings of virtual platforms (QEMU's `virt`
/// machine, crosvm, the Android emulator), lowercase.
const BOARD_MARKERS: &[&str] = &[
    "qemu",
    "dummy-virt",
    "kvm",
    "xen",
    "crosvm",
    "ranchu",
    "goldfish",
];

const BOARD_FILES: &[&str] = &[
    "/proc/device-tree/compatible",
    "/proc/device-tree/model",
    "/sys/firmware/devicetree/base/compatible",
    "/proc/cmdline",
];

/// The first marker of a hypervisor or WSL, or `None` on bare metal.
/// `read` returns a file's contents, `env` an environment variable.
pub(super) fn evidence(
    read: impl Fn(&str) -> Option<String>,
    env: impl Fn(&str) -> Option<String>,
) -> Option<&'static str> {
    if read("/sys/hypervisor/type").is_some_and(|kind| !kind.trim().is_empty()) {
        return Some("/sys/hypervisor/type");
    }
    let Some(cpuinfo) = read("/proc/cpuinfo") else {
        return Some("/proc/cpuinfo unreadable");
    };
    for line in cpuinfo.lines() {
        let lower = line.to_ascii_lowercase();
        let Some((key, value)) = lower.split_once(':') else {
            continue;
        };
        let key = key.trim();
        if (key == "flags" || key == "features")
            && value.split_whitespace().any(|flag| flag == "hypervisor")
        {
            return Some("cpu hypervisor flag");
        }
        if key == "hardware" && BOARD_MARKERS.iter().any(|marker| value.contains(marker)) {
            return Some("cpu hardware string");
        }
    }
    if DMI_FILES.iter().any(|path| {
        read(path).is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            DMI_MARKERS.iter().any(|marker| value.contains(marker))
        })
    }) {
        return Some("dmi vendor string");
    }
    if BOARD_FILES.iter().any(|path| {
        read(path).is_some_and(|value| {
            let value = value.to_ascii_lowercase();
            BOARD_MARKERS.iter().any(|marker| value.contains(marker))
        })
    }) {
        return Some("device tree or boot command line");
    }
    if env("WSL_DISTRO_NAME").is_some()
        || env("WSL_INTEROP").is_some()
        || read("/proc/sys/fs/binfmt_misc/WSLInterop").is_some()
        || ["/proc/sys/kernel/osrelease", "/proc/version"]
            .iter()
            .any(|path| {
                read(path).is_some_and(|value| {
                    let value = value.to_ascii_lowercase();
                    value.contains("microsoft") || value.contains("wsl")
                })
            })
    {
        return Some("wsl");
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::collections::HashMap;

    const BARE_CPUINFO: &str = "processor\t: 0\nvendor_id\t: GenuineIntel\nflags\t\t: fpu vme de pse tsc msr sse sse2 ht\n";

    /// A bare-metal x86 machine, plus `extra` files.
    fn host(extra: &[(&str, &str)]) -> HashMap<String, String> {
        let mut files: HashMap<String, String> = [
            ("/proc/cpuinfo", BARE_CPUINFO),
            ("/sys/class/dmi/id/sys_vendor", "Dell Inc.\n"),
            ("/sys/class/dmi/id/product_name", "XPS 13 9310\n"),
            ("/proc/sys/kernel/osrelease", "6.8.0-45-generic\n"),
            (
                "/proc/version",
                "Linux version 6.8.0-45-generic (buildd@lcy02)\n",
            ),
        ]
        .into_iter()
        .map(|(path, value)| (path.to_string(), value.to_string()))
        .collect();
        for (path, value) in extra {
            files.insert((*path).to_string(), (*value).to_string());
        }
        files
    }

    fn probe(files: &HashMap<String, String>, vars: &[&str]) -> Option<&'static str> {
        evidence(
            |path| files.get(path).cloned(),
            |name| vars.contains(&name).then(|| "1".to_string()),
        )
    }

    #[test]
    fn bare_metal_reads_as_bare_metal() {
        assert_eq!(probe(&host(&[]), &[]), None);
        let phone = host(&[(
            "/proc/cpuinfo",
            "processor\t: 0\nFeatures\t: fp asimd evtstrm aes pmull sha1\nHardware\t: Qualcomm Technologies, Inc SM8550\n",
        )]);
        assert_eq!(probe(&phone, &[]), None);
    }

    #[test]
    fn every_hypervisor_marker_reads_as_a_vm() {
        let vm_cpuinfo = "flags\t\t: fpu vme hypervisor sse2\n";
        let cases: Vec<HashMap<String, String>> = vec![
            host(&[("/sys/hypervisor/type", "xen\n")]),
            host(&[("/proc/cpuinfo", vm_cpuinfo)]),
            host(&[("/sys/class/dmi/id/sys_vendor", "QEMU\n")]),
            host(&[(
                "/sys/class/dmi/id/product_name",
                "VMware Virtual Platform\n",
            )]),
            host(&[("/sys/class/dmi/id/product_name", "Virtual Machine\n")]),
            host(&[("/sys/class/dmi/id/bios_vendor", "innotek GmbH\n")]),
            host(&[("/sys/class/dmi/id/sys_vendor", "Amazon EC2\n")]),
            host(&[("/proc/device-tree/compatible", "linux,dummy-virt\0")]),
            host(&[("/proc/cmdline", "androidboot.hardware=ranchu quiet")]),
            host(&[(
                "/proc/cpuinfo",
                "processor\t: 0\nFeatures\t: fp asimd\nHardware\t: Goldfish\n",
            )]),
            host(&[(
                "/proc/sys/kernel/osrelease",
                "5.15.153.1-microsoft-standard-WSL2\n",
            )]),
            host(&[("/proc/sys/fs/binfmt_misc/WSLInterop", "enabled\n")]),
        ];
        for (index, files) in cases.iter().enumerate() {
            assert!(
                probe(files, &[]).is_some(),
                "case {index} read as bare metal"
            );
        }
        assert_eq!(probe(&host(&[]), &["WSL_DISTRO_NAME"]), Some("wsl"));
    }

    #[test]
    fn an_unreadable_cpuinfo_reads_as_a_vm() {
        let mut files = host(&[]);
        files.remove("/proc/cpuinfo");
        assert_eq!(probe(&files, &[]), Some("/proc/cpuinfo unreadable"));
    }

    #[test]
    fn an_empty_sys_hypervisor_type_is_not_evidence() {
        assert_eq!(probe(&host(&[("/sys/hypervisor/type", "\n")]), &[]), None);
    }
}
