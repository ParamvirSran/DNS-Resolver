import socket

import dns

server_address = "localhost"
server_port = 6969
domain_name = "example.com"
TYPE_A = 1


# main function to make a DNS query to the server and print the response
def main():
    query = dns.build_query(domain_name, TYPE_A)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(query, (server_address, server_port))
        try:

            data, addr = sock.recvfrom(1024)
            response = dns.parse_dns_packet(data)
            ip_address = dns.get_answer(response)
            print(f"Received response from {addr} with IP address {ip_address}")

        except Exception as e:
            print(f"An error occurred: {e}")
            return


if __name__ == "__main__":
    main()
