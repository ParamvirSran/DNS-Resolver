from dataclasses import dataclass

from dnsQuery import DNSHeader, DNSQuestion, build_query


@dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes


import struct


def parse_header(reader):
    header_data = reader.read(12)
    if len(header_data) != 12:
        raise ValueError("Incomplete DNS header")
    return DNSHeader(*struct.unpack("!HHHHHH", header_data))


from io import BytesIO


def parse_question(reader):
    name = decode_name(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack("!HH", data)
    return DNSQuestion(name, type_, class_)


from io import BytesIO


def decode_name(reader):
    name = b""
    while True:
        length = ord(reader.read(1))
        if length == 0:
            break
        if length & 0b11000000:
            offset = ((length & 0b00111111) << 8) + ord(reader.read(1))
            saved_position = reader.tell()
            reader.seek(offset)
            name += decode_name(reader)
            reader.seek(saved_position)
            break
        name += reader.read(length) + b"."
    return name


def parse_record(reader):
    name = decode_name(reader)
    data = reader.read(10)
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
    data = reader.read(data_len)
    return DNSRecord(name, type_, class_, ttl, data)


from typing import List


@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]


def parse_dns_packet(data):
    reader = BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]
    return DNSPacket(header, questions, answers, authorities, additionals)


def ip_to_string(ip):
    return ".".join([str(x) for x in ip])


import socket

TYPE_A = 1


def lookup_domain(domain_name):
    query = build_query(domain_name, TYPE_A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))
    data, _ = sock.recvfrom(1024)
    response = parse_dns_packet(data)
    return ip_to_string(response.answers[0].data)
