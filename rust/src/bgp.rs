use byteorder::{BigEndian, ReadBytesExt};
use std::io::{self, Cursor};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpMessageType {
    Open,
    Update,
    Notification,
    Keepalive,
    RouteRefresh,
    Unknown(u8),
}

impl From<u8> for BgpMessageType {
    fn from(t: u8) -> Self {
        match t {
            1 => BgpMessageType::Open,
            2 => BgpMessageType::Update,
            3 => BgpMessageType::Notification,
            4 => BgpMessageType::Keepalive,
            5 => BgpMessageType::RouteRefresh,
            t => BgpMessageType::Unknown(t),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpAttributeType {
    Origin,
    AsPath,
    NextHop,
    MultiExitDisc,
    LocalPref,
    AtomicAggregate,
    Aggregator,
    Communities,
    OriginatorId,
    ClusterList,
    MpReachNlri,
    MpUnreachNlri,
    ExtendedCommunities,
    As4Path,
    As4Aggregator,
    LargeCommunities,
    Unknown(u8),
}

impl From<u8> for BgpAttributeType {
    fn from(t: u8) -> Self {
        match t {
            1 => BgpAttributeType::Origin,
            2 => BgpAttributeType::AsPath,
            3 => BgpAttributeType::NextHop,
            4 => BgpAttributeType::MultiExitDisc,
            5 => BgpAttributeType::LocalPref,
            6 => BgpAttributeType::AtomicAggregate,
            7 => BgpAttributeType::Aggregator,
            8 => BgpAttributeType::Communities,
            9 => BgpAttributeType::OriginatorId,
            10 => BgpAttributeType::ClusterList,
            14 => BgpAttributeType::MpReachNlri,
            15 => BgpAttributeType::MpUnreachNlri,
            16 => BgpAttributeType::ExtendedCommunities,
            17 => BgpAttributeType::As4Path,
            18 => BgpAttributeType::As4Aggregator,
            32 => BgpAttributeType::LargeCommunities,
            t => BgpAttributeType::Unknown(t),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BgpAttributeFlags {
    pub optional: bool,
    pub transitive: bool,
    pub partial: bool,
    pub extended_length: bool,
}

impl From<u8> for BgpAttributeFlags {
    fn from(f: u8) -> Self {
        BgpAttributeFlags {
            optional: (f & 0x80) != 0,
            transitive: (f & 0x40) != 0,
            partial: (f & 0x20) != 0,
            extended_length: (f & 0x10) != 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BgpAttribute {
    pub flags: BgpAttributeFlags,
    pub attr_type: BgpAttributeType,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BgpHeader {
    pub marker: [u8; 16],
    pub length: u16,
    pub msg_type: BgpMessageType,
}

#[derive(Debug, Clone)]
pub struct BgpPrefix {
    pub path_id: Option<u32>,
    pub length: u8,
    pub prefix: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BgpUpdateMessage {
    pub withdrawn_routes: Vec<BgpPrefix>,
    pub attributes: Vec<BgpAttribute>,
    pub nlri: Vec<BgpPrefix>,
}

#[derive(Debug, Clone)]
pub struct BgpAsPathSegment {
    pub seg_type: u8, // 1: AS_SET, 2: AS_SEQUENCE
    pub asns: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct BgpAsPath {
    pub segments: Vec<BgpAsPathSegment>,
}

pub struct BgpParser;

impl BgpParser {
    pub fn parse_update(mut data: &[u8], has_add_path: bool) -> io::Result<BgpUpdateMessage> {
        let mut rdr = Cursor::new(data);
        let withdrawn_len = rdr.read_u16::<BigEndian>()?;
        let withdrawn_data = &data[2..2 + withdrawn_len as usize];
        let withdrawn_routes = Self::parse_prefixes(withdrawn_data, has_add_path)?;

        let attr_offset = 2 + withdrawn_len as usize;
        let attr_len = Cursor::new(&data[attr_offset..]).read_u16::<BigEndian>()?;
        let attr_data = &data[attr_offset + 2..attr_offset + 2 + attr_len as usize];
        let attributes = Self::parse_attributes(attr_data)?;

        let nlri_offset = attr_offset + 2 + attr_len as usize;
        let nlri_data = &data[nlri_offset..];
        let nlri = Self::parse_prefixes(nlri_data, has_add_path)?;

        Ok(BgpUpdateMessage {
            withdrawn_routes,
            attributes,
            nlri,
        })
    }

    pub fn parse_attributes(mut data: &[u8]) -> io::Result<Vec<BgpAttribute>> {
        let mut attributes = Vec::new();
        while !data.is_empty() {
            if data.len() < 2 {
                break;
            }
            let flags = BgpAttributeFlags::from(data[0]);
            let type_code = BgpAttributeType::from(data[1]);
            data = &data[2..];

            let length = if flags.extended_length {
                if data.len() < 2 {
                    break;
                }
                let len = Cursor::new(data).read_u16::<BigEndian>()?;
                data = &data[2..];
                len as usize
            } else {
                if data.is_empty() {
                    break;
                }
                let len = data[0] as usize;
                data = &data[1..];
                len
            };

            if data.len() < length {
                break;
            }
            let value = data[..length].to_vec();
            data = &data[length..];

            attributes.push(BgpAttribute {
                flags,
                attr_type: type_code,
                value,
            });
        }
        Ok(attributes)
    }

    pub fn parse_prefixes(mut data: &[u8], has_add_path: bool) -> io::Result<Vec<BgpPrefix>> {
        let mut prefixes = Vec::new();
        while !data.is_empty() {
            let path_id = if has_add_path {
                if data.len() < 4 {
                    break;
                }
                let id = Cursor::new(data).read_u32::<BigEndian>()?;
                data = &data[4..];
                Some(id)
            } else {
                None
            };

            if data.is_empty() {
                break;
            }
            let length = data[0];
            data = &data[1..];

            let bytes_to_read = (length as usize + 7) / 8;
            if data.len() < bytes_to_read {
                break;
            }
            let prefix = data[..bytes_to_read].to_vec();
            data = &data[bytes_to_read..];

            prefixes.push(BgpPrefix {
                path_id,
                length,
                prefix,
            });
        }
        Ok(prefixes)
    }

    pub fn prefix_to_string(prefix: &BgpPrefix, is_ipv6: bool) -> String {
        let full_prefix = if !is_ipv6 {
            let mut addr = [0u8; 4];
            for i in 0..prefix.prefix.len() {
                addr[i] = prefix.prefix[i];
            }
            format!("{}", Ipv4Addr::from(addr))
        } else {
            let mut addr = [0u8; 16];
            for i in 0..prefix.prefix.len() {
                addr[i] = prefix.prefix[i];
            }
            format!("{}", Ipv6Addr::from(addr))
        };
        format!("{}/{}", full_prefix, prefix.length)
    }

    pub fn parse_message(data: &[u8]) -> io::Result<Option<(BgpHeader, Vec<u8>)>> {
        if data.len() < 19 {
            return Ok(None);
        }
        let mut marker = [0u8; 16];
        marker.copy_from_slice(&data[0..16]);
        let mut rdr = Cursor::new(&data[16..19]);
        let length = rdr.read_u16::<BigEndian>()?;
        let msg_type = BgpMessageType::from(rdr.read_u8()?);

        if data.len() < length as usize {
            return Ok(None);
        }
        let payload = data[19..length as usize].to_vec();
        Ok(Some((
            BgpHeader {
                marker,
                length,
                msg_type,
            },
            payload,
        )))
    }

    pub fn decode_as_path(mut data: &[u8], is_as4: bool) -> io::Result<BgpAsPath> {
        let mut segments = Vec::new();
        while !data.is_empty() {
            if data.len() < 2 {
                break;
            }
            let seg_type = data[0];
            let count = data[1] as usize;
            let asn_size = if is_as4 { 4 } else { 2 };
            data = &data[2..];

            if data.len() < count * asn_size {
                break;
            }

            let mut asns = Vec::new();
            let mut rdr = Cursor::new(data);
            for _ in 0..count {
                if is_as4 {
                    asns.push(rdr.read_u32::<BigEndian>()?);
                } else {
                    asns.push(rdr.read_u16::<BigEndian>()? as u32);
                }
            }
            data = &data[count * asn_size..];

            segments.push(BgpAsPathSegment { seg_type, asns });
        }
        Ok(BgpAsPath { segments })
    }

    pub fn as_path_to_string(as_path: &BgpAsPath) -> String {
        let mut s = String::new();
        for seg in &as_path.segments {
            s.push(if seg.seg_type == 1 { '{' } else { '(' });
            for (i, asn) in seg.asns.iter().enumerate() {
                if i > 0 {
                    s.push(' ');
                }
                s.push_str(&asn.to_string());
            }
            s.push(if seg.seg_type == 1 { '}' } else { ')' });
        }
        s
    }

    pub fn decode_communities(data: &[u8]) -> io::Result<Vec<String>> {
        let mut communities = Vec::new();
        let mut rdr = Cursor::new(data);
        while (rdr.position() as usize) + 4 <= data.len() {
            let asn = rdr.read_u16::<BigEndian>()?;
            let val = rdr.read_u16::<BigEndian>()?;
            communities.push(format!("{}:{}", asn, val));
        }
        Ok(communities)
    }

    pub fn origin_to_string(origin: u8) -> String {
        match origin {
            0 => "IGP".to_string(),
            1 => "EGP".to_string(),
            2 => "INCOMPLETE".to_string(),
            _ => format!("UNKNOWN({})", origin),
        }
    }

    pub fn attribute_type_to_name(t: &BgpAttributeType) -> String {
        match t {
            BgpAttributeType::Origin => "ORIGIN".to_string(),
            BgpAttributeType::AsPath => "AS_PATH".to_string(),
            BgpAttributeType::NextHop => "NEXT_HOP".to_string(),
            BgpAttributeType::MultiExitDisc => "MULTI_EXIT_DISC".to_string(),
            BgpAttributeType::LocalPref => "LOCAL_PREF".to_string(),
            BgpAttributeType::AtomicAggregate => "ATOMIC_AGGREGATE".to_string(),
            BgpAttributeType::Aggregator => "AGGREGATOR".to_string(),
            BgpAttributeType::Communities => "COMMUNITIES".to_string(),
            BgpAttributeType::MpReachNlri => "MP_REACH_NLRI".to_string(),
            BgpAttributeType::MpUnreachNlri => "MP_UNREACH_NLRI".to_string(),
            BgpAttributeType::As4Path => "AS4_PATH".to_string(),
            BgpAttributeType::Unknown(code) => format!("UNKNOWN({})", code),
            _ => format!("{:?}", t).to_uppercase(),
        }
    }
}
