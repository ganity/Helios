use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{
        Name, RData, Record,
        rdata::{A, AAAA},
    },
};
use std::{net::IpAddr, str::FromStr};

pub fn build_dns_response(mut request: Message, domain: &str, ip: IpAddr, ttl: u32) -> Result<Message, String> {
    let name = Name::from_str(domain).map_err(|e| e.to_string())?;
    let record = match ip {
        IpAddr::V4(ip) => Record::from_rdata(name.clone(), ttl, RData::A(A(ip))),
        IpAddr::V6(ip) => Record::from_rdata(name, ttl, RData::AAAA(AAAA(ip))),
    };

    // We must indicate that this message is a response. Otherwise, implementations may not
    // recognize it.
    request.metadata.message_type = MessageType::Response;

    request.add_answer(record);
    Ok(request)
}

pub fn remove_ipv6_entries(message: &mut Message) {
    message.answers.retain(|answer| !matches!(&answer.data, RData::AAAA(_)));
}

pub fn extract_ipaddr_from_dns_message(message: &Message) -> Result<IpAddr, String> {
    if message.metadata.response_code != ResponseCode::NoError {
        return Err(format!("{:?}", message.metadata.response_code));
    }
    let mut cname = None;
    for answer in &message.answers {
        match &answer.data {
            RData::A(addr) => {
                return Ok(IpAddr::V4((*addr).into()));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6((*addr).into()));
            }
            RData::CNAME(name) => {
                cname = Some(name.to_utf8());
            }
            _ => {}
        }
    }
    if let Some(cname) = cname {
        return Err(cname);
    }
    Err(format!("{:?}", message.answers))
}

pub fn extract_domain_from_dns_message(message: &Message) -> Result<String, String> {
    let query = message.queries.first().ok_or("DnsRequest no query body")?;
    let name = query.name().to_string();
    Ok(name)
}

pub fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> Result<Message, String> {
    if used_by_tcp {
        if data.len() < 2 {
            return Err("invalid dns data".into());
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or("invalid dns data")?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| e.to_string())?;
    Ok(message)
}

/// Keep incomplete TCP frames across reads; loopback writes are not message boundaries.
pub(crate) fn take_tcp_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.len() < 2 {
        return None;
    }
    let length = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
    if buffer.len() < length + 2 {
        return None;
    }
    let frame = buffer[2..length + 2].to_vec();
    buffer.drain(..length + 2);
    Some(frame)
}

#[cfg(test)]
mod framing_tests {
    #[test]
    fn dns_tcp_retains_split_length_body_and_coalesced_frames() {
        let mut pending = vec![0];
        assert_eq!(super::take_tcp_frame(&mut pending), None);
        pending.extend_from_slice(&[3, 1]);
        assert_eq!(super::take_tcp_frame(&mut pending), None);
        pending.extend_from_slice(&[2, 3, 0, 1, 4, 0]);
        assert_eq!(super::take_tcp_frame(&mut pending), Some(vec![1, 2, 3]));
        assert_eq!(super::take_tcp_frame(&mut pending), Some(vec![4]));
        assert_eq!(super::take_tcp_frame(&mut pending), None);
        assert_eq!(pending, [0]);
        pending.extend_from_slice(&[1, 5]);
        assert_eq!(super::take_tcp_frame(&mut pending), Some(vec![5]));
        assert!(pending.is_empty());
    }
}
