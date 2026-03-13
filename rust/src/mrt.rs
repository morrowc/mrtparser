use byteorder::{BigEndian, ReadBytesExt};
use serde::Serialize;
use std::io::{self, Cursor, Read};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MrtType {
    Ospfv2,
    TableDump,
    TableDumpV2,
    Bgp4mp,
    Bgp4mpEt,
    Isis,
    IsisEt,
    Ospfv3,
    Ospfv3Et,
    Unknown(u16),
}

impl From<u16> for MrtType {
    fn from(t: u16) -> Self {
        match t {
            11 => MrtType::Ospfv2,
            12 => MrtType::TableDump,
            13 => MrtType::TableDumpV2,
            16 => MrtType::Bgp4mp,
            17 => MrtType::Bgp4mpEt,
            32 => MrtType::Isis,
            33 => MrtType::IsisEt,
            48 => MrtType::Ospfv3,
            49 => MrtType::Ospfv3Et,
            t => MrtType::Unknown(t),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TableDumpV2Subtype {
    PeerIndexTable,
    RibIpv4Unicast,
    RibIpv4Multicast,
    RibIpv6Unicast,
    RibIpv6Multicast,
    RibGeneric,
    RibIpv4UnicastAddpath,
    RibIpv4MulticastAddpath,
    RibIpv6UnicastAddpath,
    RibIpv6MulticastAddpath,
    RibGenericAddpath,
    Unknown(u16),
}

impl From<u16> for TableDumpV2Subtype {
    fn from(s: u16) -> Self {
        match s {
            1 => TableDumpV2Subtype::PeerIndexTable,
            2 => TableDumpV2Subtype::RibIpv4Unicast,
            3 => TableDumpV2Subtype::RibIpv4Multicast,
            4 => TableDumpV2Subtype::RibIpv6Unicast,
            5 => TableDumpV2Subtype::RibIpv6Multicast,
            6 => TableDumpV2Subtype::RibGeneric,
            8 => TableDumpV2Subtype::RibIpv4UnicastAddpath,
            9 => TableDumpV2Subtype::RibIpv4MulticastAddpath,
            10 => TableDumpV2Subtype::RibIpv6UnicastAddpath,
            11 => TableDumpV2Subtype::RibIpv6MulticastAddpath,
            12 => TableDumpV2Subtype::RibGenericAddpath,
            s => TableDumpV2Subtype::Unknown(s),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Bgp4mpSubtype {
    StateChange,
    Message,
    MessageAs4,
    StateChangeAs4,
    MessageLocal,
    MessageAs4Local,
    MessageAddpath,
    MessageAs4Addpath,
    MessageLocalAddpath,
    MessageAs4LocalAddpath,
    Unknown(u16),
}

impl From<u16> for Bgp4mpSubtype {
    fn from(s: u16) -> Self {
        match s {
            0 => Bgp4mpSubtype::StateChange,
            1 => Bgp4mpSubtype::Message,
            4 => Bgp4mpSubtype::MessageAs4,
            5 => Bgp4mpSubtype::StateChangeAs4,
            6 => Bgp4mpSubtype::MessageLocal,
            7 => Bgp4mpSubtype::MessageAs4Local,
            8 => Bgp4mpSubtype::MessageAddpath,
            9 => Bgp4mpSubtype::MessageAs4Addpath,
            10 => Bgp4mpSubtype::MessageLocalAddpath,
            11 => Bgp4mpSubtype::MessageAs4LocalAddpath,
            s => Bgp4mpSubtype::Unknown(s),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MrtHeader {
    pub timestamp: u32,
    pub mrt_type: MrtType,
    pub subtype: u16,
    pub length: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerEntry {
    pub peer_type: u8,
    pub peer_bgp_id: u32,
    pub peer_ip: String,
    pub peer_as: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerIndexTable {
    pub collector_bgp_id: u32,
    pub view_name: String,
    pub peers: Vec<PeerEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RibEntry {
    pub peer_index: u16,
    pub originated_time: u32,
    pub attributes: Vec<crate::bgp::BgpAttribute>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RibRecord {
    pub sequence_number: u32,
    pub prefix_length: u8,
    pub prefix: Vec<u8>,
    pub entries: Vec<RibEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MrtRecord {
    pub header: MrtHeader,
    pub microsecond_timestamp: Option<u32>,
    pub data: Vec<u8>,
    pub peer_index_table: Option<PeerIndexTable>,
    pub rib_record: Option<RibRecord>,
}

impl MrtRecord {
    pub fn parse<R: Read>(mut reader: R) -> io::Result<Option<Self>> {
        let mut header_buf = [0u8; 12];
        if reader.read_exact(&mut header_buf).is_err() {
            return Ok(None);
        }

        let mut rdr = Cursor::new(header_buf);
        let timestamp = rdr.read_u32::<BigEndian>()?;
        let type_raw = rdr.read_u16::<BigEndian>()?;
        let subtype = rdr.read_u16::<BigEndian>()?;
        let length = rdr.read_u32::<BigEndian>()?;

        let mrt_type = MrtType::from(type_raw);
        let mut has_et = false;
        match mrt_type {
            MrtType::Bgp4mpEt | MrtType::IsisEt | MrtType::Ospfv3Et => has_et = true,
            _ => {}
        }

        let mut microsecond_timestamp = None;
        let mut remaining_length = length;

        if has_et {
            microsecond_timestamp = Some(reader.read_u32::<BigEndian>()?);
            remaining_length -= 4;
        }

        let mut data = vec![0u8; remaining_length as usize];
        reader.read_exact(&mut data)?;

        let mut record = MrtRecord {
            header: MrtHeader {
                timestamp,
                mrt_type,
                subtype,
                length,
            },
            microsecond_timestamp,
            data,
            peer_index_table: None,
            rib_record: None,
        };

        if record.header.mrt_type == MrtType::TableDumpV2 {
            record.parse_table_dump_v2()?;
        }

        Ok(Some(record))
    }

    fn parse_table_dump_v2(&mut self) -> io::Result<()> {
        let subtype = TableDumpV2Subtype::from(self.header.subtype);
        let mut rdr = Cursor::new(&self.data);

        match subtype {
            TableDumpV2Subtype::PeerIndexTable => {
                if self.data.len() < 4 {
                    return Ok(());
                }
                let collector_bgp_id = rdr.read_u32::<BigEndian>()?;
                let view_name_len = rdr.read_u16::<BigEndian>()?;
                let mut view_name_buf = vec![0u8; view_name_len as usize];
                rdr.read_exact(&mut view_name_buf)?;
                let view_name = String::from_utf8_lossy(&view_name_buf).to_string();

                let peer_count = rdr.read_u16::<BigEndian>()?;
                let mut peers = Vec::new();

                for _ in 0..peer_count {
                    let peer_type = rdr.read_u8()?;
                    let peer_bgp_id = rdr.read_u32::<BigEndian>()?;

                    let is_ipv6 = (peer_type & 0x01) != 0;
                    let is_as4 = (peer_type & 0x02) != 0;

                    let peer_ip = if is_ipv6 {
                        let mut addr = [0u8; 16];
                        rdr.read_exact(&mut addr)?;
                        format!("{}", std::net::Ipv6Addr::from(addr))
                    } else {
                        let mut addr = [0u8; 4];
                        rdr.read_exact(&mut addr)?;
                        format!("{}", std::net::Ipv4Addr::from(addr))
                    };

                    let peer_as = if is_as4 {
                        rdr.read_u32::<BigEndian>()?
                    } else {
                        rdr.read_u16::<BigEndian>()? as u32
                    };

                    peers.push(PeerEntry {
                        peer_type,
                        peer_bgp_id,
                        peer_ip,
                        peer_as,
                    });
                }
                self.peer_index_table = Some(PeerIndexTable {
                    collector_bgp_id,
                    view_name,
                    peers,
                });
            }
            TableDumpV2Subtype::RibIpv4Unicast
            | TableDumpV2Subtype::RibIpv4Multicast
            | TableDumpV2Subtype::RibIpv6Unicast
            | TableDumpV2Subtype::RibIpv6Multicast
            | TableDumpV2Subtype::RibGeneric
            | TableDumpV2Subtype::RibIpv4UnicastAddpath
            | TableDumpV2Subtype::RibIpv4MulticastAddpath
            | TableDumpV2Subtype::RibIpv6UnicastAddpath
            | TableDumpV2Subtype::RibIpv6MulticastAddpath
            | TableDumpV2Subtype::RibGenericAddpath => {
                if self.data.len() < 4 {
                    return Ok(());
                }
                let sequence_number = rdr.read_u32::<BigEndian>()?;
                let prefix_length = rdr.read_u8()?;
                let prefix_bytes = (prefix_length as usize).div_ceil(8);
                let mut prefix = vec![0u8; prefix_bytes];
                rdr.read_exact(&mut prefix)?;

                let entry_count = rdr.read_u16::<BigEndian>()?;
                let mut entries = Vec::new();

                for _ in 0..entry_count {
                    let peer_index = rdr.read_u16::<BigEndian>()?;
                    let originated_time = rdr.read_u32::<BigEndian>()?;
                    let attr_len = rdr.read_u16::<BigEndian>()?;
                    let mut attr_data = vec![0u8; attr_len as usize];
                    rdr.read_exact(&mut attr_data)?;

                    let attributes = crate::bgp::BgpParser::parse_attributes(&attr_data)?;
                    entries.push(RibEntry {
                        peer_index,
                        originated_time,
                        attributes,
                    });
                }

                self.rib_record = Some(RibRecord {
                    sequence_number,
                    prefix_length,
                    prefix,
                    entries,
                });
            }
            _ => {}
        }
        Ok(())
    }

    pub fn type_to_string(t: MrtType) -> String {
        match t {
            MrtType::Unknown(code) => format!("UNKNOWN({})", code),
            _ => format!("{:?}", t).to_uppercase(),
        }
    }

    pub fn subtype_to_string(mrt_type: MrtType, subtype: u16) -> String {
        match mrt_type {
            MrtType::TableDumpV2 => {
                format!("{:?}", TableDumpV2Subtype::from(subtype)).to_uppercase()
            }
            MrtType::Bgp4mp | MrtType::Bgp4mpEt => {
                format!("{:?}", Bgp4mpSubtype::from(subtype)).to_uppercase()
            }
            _ => subtype.to_string(),
        }
    }
}
