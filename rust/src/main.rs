use bzip2::read::BzDecoder;
use clap::Parser;
use flate2::read::GzDecoder;
use mrtparser::bgp::{BgpAttributeType, BgpMessageType, BgpParser};
use mrtparser::mrt::{Bgp4mpSubtype, MrtRecord, MrtType};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    utc: bool,

    #[arg(long)]
    single_line: bool,

    #[arg(long)]
    json: bool,

    #[arg(num_args = 1..)]
    files: Vec<String>,
}

fn format_timestamp(timestamp: u32, utc: bool) -> String {
    if utc {
        chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| timestamp.to_string())
    } else {
        timestamp.to_string()
    }
}

fn process_file(filename: &str, args: &Args) -> io::Result<()> {
    let path = Path::new(filename);
    let file = File::open(path)?;
    let reader: Box<dyn Read> = if filename.ends_with(".bz2") {
        Box::new(BzDecoder::new(file))
    } else if filename.ends_with(".gz") {
        Box::new(GzDecoder::new(file))
    } else {
        Box::new(file)
    };

    let mut buf_reader = BufReader::new(reader);
    let mut record_count = 0;

    while let Some(record) = MrtRecord::parse(&mut buf_reader)? {
        record_count += 1;

        if args.json {
            println!("{}", serde_json::to_string(&record).unwrap());
            continue;
        }

        let mut output = String::new();
        if args.single_line {
            output.push_str(&format!("Record {}: ", record_count));
            output.push_str(&format!(
                "Timestamp: {} ",
                format_timestamp(record.header.timestamp, args.utc)
            ));
            output.push_str(&format!(
                "Type: {} ",
                MrtRecord::type_to_string(record.header.mrt_type)
            ));
            output.push_str(&format!(
                "Subtype: {} ",
                MrtRecord::subtype_to_string(record.header.mrt_type, record.header.subtype)
            ));
            output.push_str(&format!("Length: {} ", record.header.length));
            if let Some(et) = record.microsecond_timestamp {
                output.push_str(&format!("Microsec: {} ", et));
            }
        } else {
            output.push_str(&format!("Record {}:\n", record_count));
            output.push_str(&format!(
                "  Timestamp: {}\n",
                format_timestamp(record.header.timestamp, args.utc)
            ));
            output.push_str(&format!(
                "  Type:      {}\n",
                MrtRecord::type_to_string(record.header.mrt_type)
            ));
            output.push_str(&format!(
                "  Subtype:   {}\n",
                MrtRecord::subtype_to_string(record.header.mrt_type, record.header.subtype)
            ));
            output.push_str(&format!("  Length:    {}\n", record.header.length));
            if let Some(et) = record.microsecond_timestamp {
                output.push_str(&format!("  Microsec:  {}\n", et));
            }
        }

        // BGP4MP Handling
        if record.header.mrt_type == MrtType::Bgp4mp || record.header.mrt_type == MrtType::Bgp4mpEt
        {
            let subtype = Bgp4mpSubtype::from(record.header.subtype);
            let is_as4 = matches!(
                subtype,
                Bgp4mpSubtype::MessageAs4
                    | Bgp4mpSubtype::MessageAs4Local
                    | Bgp4mpSubtype::MessageAs4Addpath
                    | Bgp4mpSubtype::MessageAs4LocalAddpath
            );
            let _has_add_path = matches!(
                subtype,
                Bgp4mpSubtype::MessageAs4Addpath
                    | Bgp4mpSubtype::MessageAs4LocalAddpath
                    | Bgp4mpSubtype::MessageAddpath
                    | Bgp4mpSubtype::MessageLocalAddpath
            );

            let mut offset = if is_as4 { 8 } else { 4 };
            offset += 2; // Peer AS to Peer IP
            if record.data.len() >= offset + 2 {
                use byteorder::{BigEndian, ReadBytesExt};
                use std::io::Cursor;
                let afi = Cursor::new(&record.data[offset..offset + 2])
                    .read_u16::<BigEndian>()
                    .unwrap_or(0);
                offset += 2;
                let ip_len = if afi == 1 { 4 } else { 16 };
                offset += ip_len * 2;

                if record.data.len() > offset
                    && let Ok(Some((bgp_header, payload))) =
                        BgpParser::parse_message(&record.data[offset..])
                {
                    if args.single_line {
                        output.push_str(&format!(
                            "BGPType: {} ",
                            BgpParser::message_type_to_name(&bgp_header.msg_type)
                        ));
                    } else {
                        output.push_str(&format!(
                            "    BGP Type: {} (Length: {})\n",
                            BgpParser::message_type_to_name(&bgp_header.msg_type),
                            bgp_header.length
                        ));
                    }

                    if bgp_header.msg_type == BgpMessageType::Update
                        && let Ok(update) = BgpParser::parse_update(&payload, _has_add_path)
                    {
                        if args.single_line {
                            if !update.withdrawn_routes.is_empty() {
                                output.push_str("Withdrawn:");
                                for p in &update.withdrawn_routes {
                                    output.push_str(&format!(
                                        " {} ",
                                        BgpParser::prefix_to_string(p, afi == 2)
                                    ));
                                }
                            }
                            if !update.nlri.is_empty() {
                                output.push_str("NLRI:");
                                for p in &update.nlri {
                                    output.push_str(&format!(
                                        " {} ",
                                        BgpParser::prefix_to_string(p, afi == 2)
                                    ));
                                }
                            }
                        } else {
                            if !update.withdrawn_routes.is_empty() {
                                output.push_str(&format!(
                                    "      Withdrawn ({}):",
                                    update.withdrawn_routes.len()
                                ));
                                for p in &update.withdrawn_routes {
                                    output.push_str(&format!(
                                        " {}",
                                        BgpParser::prefix_to_string(p, afi == 2)
                                    ));
                                }
                                output.push('\n');
                            }
                            if !update.nlri.is_empty() {
                                output.push_str(&format!("      NLRI ({}):", update.nlri.len()));
                                for p in &update.nlri {
                                    output.push_str(&format!(
                                        " {}",
                                        BgpParser::prefix_to_string(p, afi == 2)
                                    ));
                                }
                                output.push('\n');
                            }
                        }

                        for attr in update.attributes {
                            let attr_name = BgpParser::attribute_type_to_name(&attr.attr_type);
                            if args.single_line {
                                output.push_str(&format!("{} ", attr_name));
                            } else {
                                output.push_str(&format!(
                                    "        Attribute: {} (Len: {})",
                                    attr_name,
                                    attr.value.len()
                                ));
                            }

                            if attr.attr_type == BgpAttributeType::Origin && attr.value.len() == 1 {
                                let origin_str = BgpParser::origin_to_string(attr.value[0]);
                                if args.single_line {
                                    output.push_str(&format!("={} ", origin_str));
                                } else {
                                    output.push_str(&format!(" ORIGIN={}\n", origin_str));
                                }
                            } else if attr.attr_type == BgpAttributeType::AsPath
                                || attr.attr_type == BgpAttributeType::As4Path
                            {
                                if let Ok(as_path) = BgpParser::decode_as_path(
                                    &attr.value,
                                    is_as4 || attr.attr_type == BgpAttributeType::As4Path,
                                ) {
                                    let as_path_str = BgpParser::as_path_to_string(&as_path);
                                    if args.single_line {
                                        output.push_str(&format!("={} ", as_path_str));
                                    } else {
                                        output.push_str(&format!(" AS_PATH={}\n", as_path_str));
                                    }
                                } else if !args.single_line {
                                    output.push('\n');
                                }
                            } else if attr.attr_type == BgpAttributeType::NextHop
                                && attr.value.len() == 4
                            {
                                let addr = std::net::Ipv4Addr::new(
                                    attr.value[0],
                                    attr.value[1],
                                    attr.value[2],
                                    attr.value[3],
                                );
                                if args.single_line {
                                    output.push_str(&format!("={} ", addr));
                                } else {
                                    output.push_str(&format!(" NEXT_HOP={}\n", addr));
                                }
                            } else if attr.attr_type == BgpAttributeType::Communities {
                                if let Ok(communities) = BgpParser::decode_communities(&attr.value)
                                {
                                    let comm_str = communities.join(" ");
                                    if args.single_line {
                                        output.push_str(&format!("={} ", comm_str));
                                    } else {
                                        output.push_str(&format!(" COMMUNITIES={}\n", comm_str));
                                    }
                                } else if !args.single_line {
                                    output.push('\n');
                                }
                            } else if args.single_line {
                                output.push_str(&format!("[len={}] ", attr.value.len()));
                            } else {
                                output.push('\n');
                            }
                        }
                    }
                }
            }
        }

        if let Some(rib) = record.rib_record {
            if args.single_line {
                output.push_str(&format!("RIB Entries: {} ", rib.entries.len()));
            } else {
                output.push_str(&format!("    RIB Entries: {}\n", rib.entries.len()));
                for entry in rib.entries {
                    output.push_str(&format!("      Peer Index: {}\n", entry.peer_index));
                    output.push_str(&format!("      Attributes: {}\n", entry.attributes.len()));
                }
            }
        }

        println!("{}", output.trim_end());
        if record_count >= 5 && !args.single_line {
            break;
        }
    }

    Ok(())
}

fn main() {
    let args = Args::parse();

    if args.files.is_empty() {
        Args::parse_from(["mrtparser", "--help"]);
        return;
    }

    for file in &args.files {
        if args.files.len() > 1 {
            println!("Processing file: {}", file);
        }
        if let Err(e) = process_file(file, &args) {
            eprintln!("Error processing {}: {}", file, e);
        }
    }
}
