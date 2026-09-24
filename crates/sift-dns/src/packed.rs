//! A response packed for the cache.
//!
//! A `hickory_proto::op::Message` is built to be edited, not kept: every
//! `Record` is 272 bytes whatever it holds, because `RData` is an enum as
//! large as its largest variant and `Name` carries a 32-byte inline buffer, and
//! each of the four sections is a `Vec` with a capacity word of its own.  A
//! one-address answer held that way costs 512 bytes before the cache adds a
//! byte of its own; on the wire the same answer is 60.
//!
//! [`Packed`] keeps what the message *says* and none of that scaffolding, in
//! the shape Cloudflare describes for the cache behind 1.1.1.1 ("How we saved
//! 100 terabytes of memory by optimizing 1.1.1.1's DNS cache", 2026):
//!
//! - **one buffer, fixed at insertion.** A `Box<[u8]>` rather than a `Vec`,
//!   since nothing is appended once an entry is stored;
//! - **one list for every section**, with the counts saying where each ends,
//!   rather than three vectors;
//! - **record data in wire form**, so an `A` record costs its four bytes and
//!   not the size of the largest `RData` variant;
//! - **owner names elided** when they are the question's name, which for most
//!   answers is every record: a flag byte stands in for the name, and the name
//!   is cloned back from the question on the way out.  The same flag byte also
//!   covers the other two names an owner nearly always repeats -- the previous
//!   record's owner, and the target of the `CNAME` before it -- so a chain is
//!   stored as its targets alone.  Any other name, a zone's `SOA` say, is
//!   written once and pointed at afterwards, by the compression a DNS message
//!   uses.
//!
//! The encoding is lossless, and deliberately so: [`Packed::unpack`] gives back
//! the message that was packed, owner-name case included, so a cache hit
//! answers exactly what the upstream said.  Nothing outside this process ever
//! reads the format, which is why it is ours and not a DNS message: a message
//! rebuilds every owner name from its labels, and parsing names is most of
//! what unpacking costs: an elided name is a copy of one already in hand.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message, Metadata, Query};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordData, RecordType};
use hickory_proto::serialize::binary::{
    BinDecodable, BinDecoder, BinEncodable, BinEncoder, Restrict,
};

/// Set on a record whose owner is the first question's name.
const OWNER_IS_QNAME: u8 = 1;

/// Set on a record whose owner is the previous record's.
const OWNER_IS_PREVIOUS: u8 = 2;

/// Set on a record whose owner is the target of the `CNAME` before it.
const OWNER_IS_TARGET: u8 = 3;

/// The names an owner is compared with before it is written out.
///
/// Updated after every record, in the same order when packing and unpacking,
/// so both sides agree on what each flag refers to.
#[derive(Default)]
struct Recent {
    /// The last record's owner.
    owner: Option<Name>,
    /// The last record's target, if it was a `CNAME`.
    target: Option<Name>,
}

impl Recent {
    /// Notes the record just written or read.
    fn saw(&mut self, r: &Record) {
        self.owner = Some(r.name.clone());
        self.target = match &r.data {
            RData::CNAME(c) => Some(c.0.clone()),
            _ => None,
        };
    }
}

/// A response, packed for storage.
#[derive(Clone, Debug)]
pub(crate) struct Packed {
    /// The header, as it was.  Its response code already includes the high
    /// bits an OPT record carries, so nothing is merged back on the way out.
    metadata: Metadata,
    /// How many questions, answers, authorities and additionals `bytes`
    /// holds, in that order.
    counts: [u16; 4],
    /// The OPT record's fixed fields, when there is one.  Its options, if it
    /// has any, are whatever of `bytes` follows the last section.
    edns: Option<OptHead>,
    /// The questions, then every record of every section, then the OPT
    /// record's options.
    bytes: Box<[u8]>,
}

/// The part of an OPT record that is the same size in every response.
///
/// Kept beside the buffer rather than in it, because almost every answer
/// carries an OPT record and most of those carry no options: building one from
/// six bytes in hand is a fraction of decoding it as a record.
#[derive(Clone, Copy, Debug)]
struct OptHead {
    rcode_high: u8,
    version: u8,
    flags: u16,
    max_payload: u16,
}

impl Packed {
    /// Packs a response, or `None` for one that must not be stored.
    ///
    /// A signed response is refused rather than stored without its
    /// signature: the signature covers one exchange, and no upstream this
    /// server speaks to signs its answers anyway.
    pub(crate) fn pack(msg: &Message) -> Option<Self> {
        if msg.signature.is_some() {
            return None;
        }

        let count = |n: usize| u16::try_from(n).ok();
        let counts = [
            count(msg.queries.len())?,
            count(msg.answers.len())?,
            count(msg.authorities.len())?,
            count(msg.additionals.len())?,
        ];

        let qname = msg.queries.first().map(|q| &q.name);
        let mut recent = Recent::default();
        let mut buf = Vec::new();
        let mut enc = BinEncoder::new(&mut buf);
        for q in &msg.queries {
            q.emit(&mut enc).ok()?;
        }
        for r in msg
            .answers
            .iter()
            .chain(&msg.authorities)
            .chain(&msg.additionals)
        {
            emit_record(&mut enc, r, qname, &recent)?;
            recent.saw(r);
        }
        if let Some(e) = &msg.edns
            && !e.options().options.is_empty()
        {
            e.options().emit(&mut enc).ok()?;
        }

        Some(Self {
            metadata: msg.metadata,
            counts,
            edns: msg.edns.as_ref().map(|e| OptHead {
                rcode_high: e.rcode_high(),
                version: e.version(),
                flags: (*e.flags()).into(),
                max_payload: e.max_payload(),
            }),
            bytes: buf.into_boxed_slice(),
        })
    }

    /// Rebuilds the message that was packed.
    ///
    /// `None` only if the bytes do not decode, which would be a bug here
    /// rather than anything an upstream could cause: they were written by
    /// [`Packed::pack`] from a message that had already been decoded once.
    pub(crate) fn unpack(&self) -> Option<Message> {
        let mut d = BinDecoder::new(&self.bytes);
        let [queries, answers, authorities, additionals] = self.counts.map(usize::from);

        // Not `Message::query`, which draws a random ID only to have it
        // overwritten: that was a tenth of the cost of a hit.
        let m = self.metadata;
        let mut msg = Message::new(m.id, m.message_type, m.op_code);
        msg.metadata = m;
        msg.queries = (0..queries)
            .map(|_| Query::read(&mut d).ok())
            .collect::<Option<_>>()?;

        let qname = msg.queries.first().map(|q| q.name.clone());
        let mut recent = Recent::default();
        let mut section = |n: usize| {
            (0..n)
                .map(|_| {
                    let r = read_record(&mut d, qname.as_ref(), &recent)?;
                    recent.saw(&r);

                    Some(r)
                })
                .collect::<Option<Vec<_>>>()
        };
        msg.answers = section(answers)?;
        msg.authorities = section(authorities)?;
        msg.additionals = section(additionals)?;

        if let Some(head) = self.edns {
            let mut edns = Edns::new();
            edns.set_rcode_high(head.rcode_high)
                .set_version(head.version)
                .set_max_payload(head.max_payload);
            *edns.flags_mut() = head.flags.into();

            let rest = u16::try_from(d.len()).ok()?;
            if rest > 0 {
                let RData::OPT(options) =
                    RData::read(&mut d, RecordType::OPT, Restrict::new(rest)).ok()?
                else {
                    return None;
                };
                *edns.options_mut() = options;
            }
            msg.edns = Some(edns);
        }

        Some(msg)
    }

    /// The bytes held on the heap.
    pub(crate) fn heap_len(&self) -> usize {
        self.bytes.len()
    }
}

/// Writes one record: a byte saying which name the owner repeats, if any, the
/// owner name if it repeats none, then type, class, TTL, and the
/// length-prefixed record data -- the wire form of everything after the
/// owner.
fn emit_record(
    enc: &mut BinEncoder<'_>,
    r: &Record,
    qname: Option<&Name>,
    recent: &Recent,
) -> Option<()> {
    // Case-sensitively: `Name`'s `==` ignores case, and an elided name comes
    // back spelled the way the name it repeats was.
    let is = |n: Option<&Name>| n.is_some_and(|n| n.eq_case(&r.name));
    let owner = if is(qname) {
        OWNER_IS_QNAME
    } else if is(recent.owner.as_ref()) {
        OWNER_IS_PREVIOUS
    } else if is(recent.target.as_ref()) {
        OWNER_IS_TARGET
    } else {
        0
    };

    enc.emit(owner).ok()?;
    if owner == 0 {
        r.name.emit(enc).ok()?;
    }
    enc.emit_u16(r.record_type().into()).ok()?;
    enc.emit_u16(r.dns_class.into()).ok()?;
    enc.emit_u32(r.ttl).ok()?;

    let place = enc.place::<u16>().ok()?;
    // No data at all is how the wire says `Update0`, and how it is read back.
    if !r.data.is_update() {
        r.data.emit(enc).ok()?;
    }
    let len = u16::try_from(enc.len_since_place(&place)).ok()?;
    place.replace(enc, len).ok()
}

/// Reads one record written by [`emit_record`].
///
/// Mirrors `Record::read` past the owner name, including its treatment of an
/// OPT record's class and of empty record data.
fn read_record(d: &mut BinDecoder<'_>, qname: Option<&Name>, recent: &Recent) -> Option<Record> {
    let name = match d.read_u8().ok()?.unverified() {
        0 => Name::read(d).ok()?,
        OWNER_IS_QNAME => qname?.clone(),
        OWNER_IS_PREVIOUS => recent.owner.clone()?,
        OWNER_IS_TARGET => recent.target.clone()?,
        _ => return None,
    };

    let rtype = RecordType::from(d.read_u16().ok()?.unverified());
    let class = d.read_u16().ok()?.unverified();
    let class = if rtype == RecordType::OPT {
        DNSClass::for_opt(class)
    } else {
        DNSClass::from(class)
    };
    let ttl = d.read_u32().ok()?.unverified();
    let len = d.read_u16().ok()?.unverified();

    // An address is most of what a cache holds, and needs none of the
    // general path's dispatch.
    let data = if len == 0 {
        RData::Update0(rtype)
    } else if rtype == RecordType::A && len == 4 {
        let b: [u8; 4] = d.read_slice(4).ok()?.unverified().try_into().ok()?;
        RData::A(Ipv4Addr::from(b).into())
    } else if rtype == RecordType::AAAA && len == 16 {
        let b: [u8; 16] = d.read_slice(16).ok()?.unverified().try_into().ok()?;
        RData::AAAA(Ipv6Addr::from(b).into())
    } else {
        RData::read(d, rtype, Restrict::new(len)).ok()?
    };

    let mut r = Record::from_rdata(name, ttl, data);
    r.dns_class = class;

    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, ResponseCode};
    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, SOA, TXT};

    fn name(s: &str) -> Name {
        Name::from_utf8(s).unwrap()
    }

    fn response(q: &str, qtype: RecordType) -> Message {
        let mut m = Message::query();
        m.metadata.message_type = MessageType::Response;
        m.metadata.recursion_desired = true;
        m.metadata.recursion_available = true;
        m.add_query(Query::query(name(q), qtype));

        m
    }

    /// Packs and unpacks `m`, and checks that what comes back encodes to the
    /// same bytes -- the one comparison that is case-sensitive, since
    /// `Name`'s `==` is not.
    fn round_trip(m: &Message) -> Message {
        let back = Packed::pack(m).expect("packs").unpack().expect("unpacks");

        assert_eq!(back.to_vec().unwrap(), m.to_vec().unwrap());
        assert_eq!(back.metadata, m.metadata);
        assert_eq!(back.edns, m.edns);

        back
    }

    #[test]
    fn a_one_address_answer_is_a_fraction_of_the_message() {
        let q = "www.example.com.";
        let mut m = response(q, RecordType::A);
        m.answers.push(Record::from_rdata(
            name(q),
            300,
            RData::A(A::new(93, 184, 216, 34)),
        ));

        round_trip(&m);

        // The question once, then a flag byte instead of the owner name, ten
        // bytes of type, class, TTL and length, and the address.
        let packed = Packed::pack(&m).unwrap();
        assert_eq!(packed.heap_len(), 17 + 4 + 1 + 10 + 4);
    }

    #[test]
    fn a_cname_chain_keeps_every_owner() {
        let mut m = response("www.microsoft.com.", RecordType::A);
        m.answers = vec![
            Record::from_rdata(
                name("www.microsoft.com."),
                3600,
                RData::CNAME(CNAME(name("www.microsoft.com-c-3.edgekey.net."))),
            ),
            Record::from_rdata(
                name("www.microsoft.com-c-3.edgekey.net."),
                900,
                RData::CNAME(CNAME(name("e13678.dscb.akamaiedge.net."))),
            ),
            Record::from_rdata(
                name("e13678.dscb.akamaiedge.net."),
                20,
                RData::A(A::new(23, 1, 2, 3)),
            ),
        ];

        let back = round_trip(&m);
        assert_eq!(
            back.answers[2].name.to_ascii(),
            "e13678.dscb.akamaiedge.net."
        );

        // Each name after the first is a pointer to where it was written as
        // the previous record's target, so the chain is not stored twice.
        let wire = m.to_vec().unwrap().len();
        assert!(
            Packed::pack(&m).unwrap().heap_len() < wire,
            "no larger than the message it came from"
        );
    }

    #[test]
    fn a_negative_answer_keeps_its_soa_and_code() {
        let mut m = response("nope.example.com.", RecordType::AAAA);
        m.metadata.response_code = ResponseCode::NXDomain;
        m.authorities.push(Record::from_rdata(
            name("example.com."),
            3600,
            RData::SOA(SOA::new(
                name("ns.icann.org."),
                name("noc.dns.icann.org."),
                2024,
                7200,
                3600,
                1_209_600,
                3600,
            )),
        ));

        round_trip(&m);
    }

    #[test]
    fn every_section_and_the_opt_record_survive() {
        let q = "example.com.";
        let mut m = response(q, RecordType::MX);
        m.metadata.authentic_data = true;
        m.answers.push(Record::from_rdata(
            name(q),
            300,
            RData::MX(MX::new(10, name("mail.example.com."))),
        ));
        m.answers.push(Record::from_rdata(
            name(q),
            300,
            RData::TXT(TXT::new(vec!["v=spf1 -all".into()])),
        ));
        m.authorities.push(Record::from_rdata(
            name(q),
            300,
            RData::CNAME(CNAME(name("ns1.example.com."))),
        ));
        m.additionals.push(Record::from_rdata(
            name("mail.example.com."),
            300,
            RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ));

        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(true);
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "192.0.2.0".parse().unwrap(),
                24,
                24,
            )));
        m.edns = Some(edns);

        let back = round_trip(&m);
        assert_eq!(back.answers.len(), 2);
        assert_eq!(back.authorities.len(), 1);
        assert_eq!(back.additionals.len(), 1);
    }

    #[test]
    fn an_extended_response_code_keeps_its_high_bits() {
        // BADVERS is 16: the header holds its low four bits and the OPT
        // record the rest, and both have to come back.
        let mut m = response("example.com.", RecordType::A);
        m.metadata.response_code = ResponseCode::BADVERS;
        let mut edns = Edns::new();
        edns.set_rcode_high(ResponseCode::BADVERS.high());
        m.edns = Some(edns);

        let back = round_trip(&m);
        assert_eq!(back.metadata.response_code, ResponseCode::BADVERS);
    }

    #[test]
    fn owner_names_keep_their_case() {
        // `Name`'s `==` ignores case, so an owner spelled differently from the
        // question would compare equal and be elided -- and come back spelled
        // like the question.  The flag is set only for an exact match.
        // `from_ascii`, because `from_utf8` lowercases on the way in.
        let mixed = || Name::from_ascii("WwW.Example.COM.").unwrap();
        let mut m = response("example.com.", RecordType::A);
        m.queries[0].name = mixed();
        m.answers.push(Record::from_rdata(
            name("www.example.com."),
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        m.answers.push(Record::from_rdata(
            mixed(),
            60,
            RData::A(A::new(192, 0, 2, 2)),
        ));

        let back = round_trip(&m);
        assert_eq!(back.answers[0].name.to_ascii(), "www.example.com.");
        assert_eq!(back.answers[1].name.to_ascii(), "WwW.Example.COM.");
    }

    #[test]
    fn a_record_with_no_data_reads_back_the_way_the_wire_reads_it() {
        let mut m = response("example.com.", RecordType::NULL);
        m.answers
            .push(Record::update0(name("example.com."), 60, RecordType::NULL));

        round_trip(&m);
    }

    #[test]
    fn a_response_without_a_question_still_packs() {
        let mut m = Message::query();
        m.metadata.message_type = MessageType::Response;
        m.answers.push(Record::from_rdata(
            name("example.com."),
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));

        round_trip(&m);
    }
}
