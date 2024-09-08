/*
Copyright 2023 The Kubernetes Authors.

SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
*/

use anyhow::Error;
use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP_FILTERED, NLM_F_REQUEST,
};
use netlink_packet_route::{
    route::{RouteAddress, RouteAttribute, RouteFlags, RouteHeader, RouteMessage},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::net::Ipv4Addr;

const ERR_NO_IFINDEX: &str = "no ifindex found to route";
const ERR_PACKET_CONSTRUCTION: &str = "construct packet failed";

/// Returns an network interface index for a Ipv4 address (like the command `ip route get to $IP`)
pub fn if_index_for_routing_ip(ip_addr: Ipv4Addr) -> Result<u32, Error> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let mut nl_hdr = NetlinkHeader::default();

    // NNLM_F_REQUEST: Must be set on all request messages (typically from user space to kernel
    // space)
    // NLM_F_DUMP_FILTERED: Dump was filtered as requested (to filter dst ipv4)
    nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP_FILTERED;

    // construct RouteMessage
    let route_header = RouteHeader {
        address_family: AddressFamily::Inet,
        flags: RouteFlags::LookupTable,
        destination_prefix_length: 32,
        table: RouteHeader::RT_TABLE_MAIN,
        ..Default::default()
    };
    let route_attribute = RouteAttribute::Destination(RouteAddress::Inet(ip_addr));
    let mut route_message = RouteMessage::default();
    route_message.attributes = vec![route_attribute];
    route_message.header = route_header;

    // construct a message packet for netlink and serialize it to send it over the socket
    let mut packet = NetlinkMessage::new(
        nl_hdr,
        NetlinkPayload::from(RouteNetlinkMessage::GetRoute(route_message)),
    );
    packet.finalize();
    let mut buf = vec![0; packet.header.length as usize];
    // check packet
    if buf.len() != packet.buffer_len() {
        return Err(Error::msg(ERR_PACKET_CONSTRUCTION));
    }
    packet.serialize(&mut buf[..]);

    // send the serialized netlink message packet over the socket
    socket.send(&buf[..], 0)?;

    // The size of the reply is always 104 bytes in local test. (get "only one" route and the reply message_type is 24)
    // layer(bytes):
    //   netlink_message_header(16) + route_message_header(12) + route_message_attributes(76)
    // but The length of route_message_attributes is not fixed.
    // while ensuring space efficiency, adapt to the maximum payload size of the packet as much as possible.
    let mut receive_buffer = vec![0; 1024];
    let mut offset = 0;
    if let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet = <NetlinkMessage<RouteNetlinkMessage>>::deserialize(bytes)?;

            // extract returned RouteNetLinkMessage
            // message type is 24 which is defined as "add_route"(NewRoute) in request
            // no matter if it's the message type returned by the ip command or this `netlink` crate,
            // it looks strange.
            if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(message)) =
                rx_packet.payload
            {
                if let Some(RouteAttribute::Oif(idex_if)) = message
                    .attributes
                    .iter()
                    .find(|attr| matches!(attr, RouteAttribute::Oif(_)))
                {
                    return Ok(*idex_if);
                }
            }

            offset += rx_packet.header.length as usize;
            if offset >= size || rx_packet.header.length == 0 {
                Err(Error::msg(format!("{} {}", ERR_NO_IFINDEX, ip_addr)))
            }
        }
    }
    Err(Error::msg(format!("{} {}", ERR_NO_IFINDEX, ip_addr)))
}
