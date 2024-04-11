import socket

import dns

# Server address and port
server_address = "localhost"
server_port = 6969
domain_name = "example.com"
TYPE_A = 1


# main function to make a DNS query to the server and print the response using udp
def main():
    # Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Create a DNS query
    query = dns.build_query(domain_name, TYPE_A)

    # Send the query to the server
    client_socket.sendto(query, (server_address, server_port))

    # Receive the response from the server
    response, _ = client_socket.recvfrom(1024)
    print(dns.ip_to_string(response))
    client_socket.close()


if __name__ == "__main__":
    main()
