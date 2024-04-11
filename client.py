import socket

import dns

server_address = "localhost"
server_port = 6969
domain_name = "google.com"
TYPE_A = 1


# main function to make a DNS query to the server and print the response using udp
def main():
    domain = input("Enter domain name or exit: ")
    while(domain.lower() != "exit"):
        # Create a UDP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Create a DNS query
        query = dns.build_query(domain, TYPE_A)

        # Send the query to the server
        client_socket.sendto(query, (server_address, server_port))

        # Receive the response from the server
        response, _ = client_socket.recvfrom(1024)
        str_response = dns.ip_to_string(response)
        if(str_response=="0.0.0.0"):
            print("could not find ip")
        else:
            print(str_response)
        client_socket.close()
        domain = input("Enter domain name or exit: ")
    print("goodbye world")

if __name__ == "__main__":
    main()
