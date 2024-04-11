import dataclasses
import random
import socket
import struct
from dataclasses import dataclass
from io import BytesIO
from typing import List

TYPE_A = 1
CLASS_IN = 1
TYPE_NS = 2
TYPE_TXT = 16

port = 6969
address = "localhost"


# DNS Header (id, flags, num_questions, num_answers, num_authorities, num_additionals)
@dataclass
class DNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0


# DNS Question (name, type, class)
@dataclass
class DNSQuestion:
    name: bytes
    type_: int
    class_: int


# DNS Record (name, type, class, ttl, data)
@dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes


# DNS Packet (header, questions, answers, authorities, additionals)
@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]


# convert bytes to header
def header_to_bytes(header):
    fields = dataclasses.astuple(header)
    return struct.pack("!HHHHHH", *fields)


# convert question to bytes
def question_to_bytes(question):
    return question.name + struct.pack("!HH", question.type_, question.class_)


# encode a domain name as a sequence of labels prefixed by their length
def encode_dns_name(domain_name):
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"


# parse header from the reader and return a DNSHeader object
def parse_header(reader):
    items = struct.unpack("!HHHHHH", reader.read(12))
    return DNSHeader(*items)


# parse a question from the reader and return a DNSQuestion object
def parse_question(reader):
    name = decode_name(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack("!HH", data)
    return DNSQuestion(name, type_, class_)


# decode the name from the reader
def decode_name(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 192:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)


# decode the compressed name from the reader if the length is 192
def decode_compressed_name(length, reader):
    pointer_bytes = bytes([length & 63]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result


# convert an ip address to a string in dotted decimal format
def ip_to_string(ip):
    return ".".join([str(x) for x in ip])


# lookup the ip address for the given domain name
def lookup_domain(domain_name):
    query = build_query(domain_name, TYPE_A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))
    data, _ = sock.recvfrom(1024)
    response = parse_dns_packet(data)
    return ip_to_string(response.answers[0].data)


# build a DNS query for the given domain name and record type
def build_query(domain_name, record_type):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    header = DNSHeader(id=id, num_questions=1, flags=0)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + question_to_bytes(question)


# send a DNS query to the given ip address for the given domain name and record type
def send_query(ip_address, domain_name, record_type):
    query = build_query(domain_name, record_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (ip_address, 53))
    data, _ = sock.recvfrom(1024)
    return parse_dns_packet(data)


# get a dns record from the reader and return a DNSRecord object
def parse_record(reader):
    name = decode_name(reader)
    data = reader.read(10)
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
    if type_ == TYPE_NS:
        data = decode_name(reader)
    elif type_ == TYPE_A:
        data = ip_to_string(reader.read(data_len))
    else:
        data = reader.read(data_len)
    return DNSRecord(name, type_, class_, ttl, data)


# parse a dns packet from the given data and return a DNSPacket object
def parse_dns_packet(data):
    reader = BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]
    return DNSPacket(header, questions, answers, authorities, additionals)


# get the answer from the packet if it exists
def get_answer(packet):
    for x in packet.answers:
        if x.type_ == TYPE_A:
            return x.data


# get the nameserver ip from the packet if it exists
def get_nameserver_ip(packet):
    for x in packet.additionals:
        if x.type_ == TYPE_A:
            return x.data


# get the nameserver from the packet if it exists
def get_nameserver(packet):
    for x in packet.authorities:
        if x.type_ == TYPE_NS:
            return x.data.decode("utf-8")


# resolve a domain name and record type and return the ip address or nameserver ip
def resolve(domain_name, record_type):
    nameserver = "198.41.0.4"
    while True:
        print(f"Querying {nameserver} for {domain_name}")
        response = send_query(nameserver, domain_name, record_type)
        if ip := get_answer(response):
            return ip
        elif nsIP := get_nameserver_ip(response):
            nameserver = nsIP
        elif ns_domain := get_nameserver(response):
            nameserver = resolve(ns_domain, TYPE_A)
        else:
            raise Exception("something went wrong")


def ip_to_bytes(ip_address):
    try:
        return socket.inet_aton(ip_address)
    except socket.error as e:
        raise ValueError(f"Invalid IP address '{ip_address}': {e}")


# main function to start the server and listen for incoming requests to resolve domain names
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((address, port))
    print(f"DNS server listening on {address}:{port}")

    while True:
        data, addr = server.recvfrom(1024)
        request = parse_dns_packet(data)
        query = request.questions[0]
        domain_name = query.name.decode("ascii")
        record_type = query.type_
        print(f"Received query for {domain_name} ({record_type}) from {addr}")
        ip_address = resolve(domain_name, record_type)
        print(f"Resolved {domain_name} to {ip_address}")

        ipBytes = ip_to_bytes(ip_address)
        print(ipBytes)
        server.sendto(ipBytes, addr)


if __name__ == "__main__":
    main()
