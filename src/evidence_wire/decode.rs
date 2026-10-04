//! Allocation-free shape checks before the existing signed-part decoders.
//! Serde's Vec visitor otherwise trusts a hostile length hint up to 1 MiB,
//! even when bincode has a smaller byte-consumption limit.
use super::*;
use serde::de::{SeqAccess, Visitor};
use std::{fmt, marker::PhantomData, net::SocketAddr};

#[derive(Deserialize)]
struct BorrowedHello<'a> {
    #[serde(borrow)]
    announcement: &'a [u8],
    #[serde(borrow)]
    advert: &'a [u8],
    #[serde(borrow)]
    certificate: Option<&'a [u8]>,
    have_certificate: Option<[u8; 32]>,
}

pub(super) fn hello(body: &[u8]) -> io::Result<Hello> {
    let wire: BorrowedHello<'_> = codec().deserialize(body).map_err(io::Error::other)?;
    parts(wire.announcement, wire.advert, wire.certificate)?;
    Ok(Hello {
        announcement: wire.announcement.to_vec(),
        advert: wire.advert.to_vec(),
        certificate: wire.certificate.map(<[u8]>::to_vec),
        have_certificate: wire.have_certificate,
    })
}

#[derive(Deserialize)]
struct BorrowedFound<'a> {
    #[serde(borrow)]
    announcement: &'a [u8],
    #[serde(borrow)]
    advert: &'a [u8],
    certificate: Option<&'a [u8]>,
}

pub(super) fn found(body: &[u8]) -> io::Result<EvidenceRecordV1> {
    let wire: BorrowedFound<'_> = codec().deserialize(body).map_err(io::Error::other)?;
    parts(wire.announcement, wire.advert, wire.certificate)?;
    Ok(EvidenceRecordV1 {
        announcement: wire.announcement.to_vec(),
        advert: wire.advert.to_vec(),
        certificate: wire.certificate.map(<[u8]>::to_vec),
        relation: 0,
        stored_at_ms: 0,
    })
}

// Consume fixed-size elements without allocation and reject impossible size
// hints before the ordinary announcement decoder can reserve them.
struct DiscardSeq<T>(PhantomData<T>);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for DiscardSeq<T> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Sequence<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for Sequence<T> {
            type Value = DiscardSeq<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded evidence sequence")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let cap = crate::peer_evidence::ANNOUNCEMENT_CAP / std::mem::size_of::<T>().max(1);
                if seq.size_hint().is_some_and(|n| n > cap) {
                    return Err(serde::de::Error::custom("sequence allocation cap"));
                }
                let mut count = 0;
                while seq.next_element::<T>()?.is_some() {
                    count += 1;
                    if count > cap {
                        return Err(serde::de::Error::custom("sequence allocation cap"));
                    }
                }
                Ok(DiscardSeq(PhantomData))
            }
        }
        d.deserialize_seq(Sequence(PhantomData))
    }
}

type Announcement<'a> = (
    AgentId,
    MachineId,
    &'a [u8],
    &'a [u8],
    DiscardSeq<SocketAddr>,
    u64,
    Option<&'a str>,
    Option<bool>,
    Option<bool>,
    Option<bool>,
    DiscardSeq<MachineId>,
    DiscardSeq<MachineId>,
    [u8; 32],
    u64,
    &'a [u8],
);
type Certificate<'a> = (&'a [u8], &'a [u8], &'a [u8], u64);
type Capabilities<'a> = (u16, bool, &'a str, usize, &'a [u8]);
type Advert<'a> = (u16, [u8; 32], [u8; 32], u64, Capabilities<'a>, &'a [u8]);

pub(super) fn parts(
    announcement: &[u8],
    advert: &[u8],
    certificate: Option<&[u8]>,
) -> io::Result<()> {
    if announcement.len() > crate::peer_evidence::ANNOUNCEMENT_CAP
        || advert.len() > crate::peer_evidence::ADVERT_CAP
        || certificate.is_some_and(|c| c.len() > crate::peer_evidence::CERTIFICATE_CAP)
    {
        return Err(invalid("evidence component cap"));
    }
    if let Some(bytes) = announcement.strip_prefix(b"X0A3") {
        let _: Announcement<'_> = codec().deserialize(bytes).map_err(io::Error::other)?;
    } else if let Some(bytes) = announcement.strip_prefix(b"X0A4") {
        let _: (Announcement<'_>, Option<&str>) =
            codec().deserialize(bytes).map_err(io::Error::other)?;
    } else {
        return Err(invalid("announcement magic"));
    }
    // EvidenceV1 is new: its producers use the canonical frozen advert base,
    // optionally followed by the signed X0CR registry trailer.
    let (_, tail) = postcard::take_from_bytes::<Advert<'_>>(advert).map_err(io::Error::other)?;
    if !tail.is_empty() {
        let bytes = tail
            .strip_prefix(crate::dm_capability::REGISTRY_TRAILER_MAGIC)
            .ok_or_else(|| invalid("advert trailer"))?;
        let (_, rest) = postcard::take_from_bytes::<(crate::dm::CapabilityRegistry, &[u8])>(bytes)
            .map_err(io::Error::other)?;
        if !rest.is_empty() {
            return Err(invalid("advert trailing bytes"));
        }
    }
    if let Some(cert) = certificate {
        if let Some(bytes) = cert.strip_prefix(b"X0C2") {
            let _: (Certificate<'_>, Option<u64>) =
                codec().deserialize(bytes).map_err(io::Error::other)?;
        } else {
            let _: Certificate<'_> = codec().deserialize(cert).map_err(io::Error::other)?;
        }
    }
    Ok(())
}
