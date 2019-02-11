import socket
import sys

from tornado import concurrent
from tqdm import tqdm

from timeit import default_timer as timer


DEFAULT_TIMEOUT = 2

# This is used for checking if a call to socket.connect_ex
# was successful.
SUCCESS = 0


def check_port(*host_port, timeout=DEFAULT_TIMEOUT):
    # print("Time out :",timeout)
    # Create and configure the socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    # print(timeout)
    # print(host_port)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    connected = sock.connect_ex(host_port) is SUCCESS

    sock.close()

    return connected


def initiating():
    global host, scan_type
    if len(sys.argv) <= 1:
        print("No terminal arguments found ! ")
        host = input("Enter host name : ")
        print("Scan type available : ")
        print("1. Fast scan")
        print("2. Normal scan [scans 1024 ports]")
        print("3. All port scan")
        try:
            scan_type = int(input("Enter scan type : "))
        except:
            sys.exit("Scan type has to be numeric")
    elif sys.argv[1] == "-h":
        print("""
            You can pass 2 parameters, first should be the host's address and second the scan type.
            There are 3 kinds of scan type:
            1. Fast Scan
            2. Normal Scan
            3. All Port Scan
            Pass the arguments as python portscan.py <host> <scan-type>

            or simply enter python portscan.py""")
        sys.exit()

    elif len(sys.argv) >= 2:
        host = sys.argv[1]
        try:
            scan_type = int(sys.argv[2])
        except:
            sys.exit("Scan type has to be numeric")
        # print(host)
        # print(scan_type)
    else:
        print(len(sys.argv))
        print("Invalid arguments found")
        print("""

                    You can pass 2 parameters, first should be the host's address and second the scan type.
                    There are 3 kinds of scan type:
                    1. Fast Scan
                    2. Normal Scan
                    3. All Port Scan
                    Pass the arguments as python portscan.py <host> <scan-type>

                    or simply enter python portscan.py""")
        sys.exit("Please provide valid arguments")


def scanning():
    try:
        global i
        if scan_type == 1:
            DEFAULT_TIMEOUT = 0.1
            print("\n==Initiating Fast Scanning==\n")
            # for i in tqdm(well_known):
            #     single_port_scan(i)

            with concurrent.futures.ProcessPoolExecutor(max_workers=500) as executor:
                futures = [executor.submit(single_port_scan, i) for i in well_known]
            print(futures)


        elif scan_type == 2:
            DEFAULT_TIMEOUT = 2
            print("\n==Initiating Normal Scanning==\n")
            # for i in tqdm(range(1024)):
            #     single_port_scan(i)

            with concurrent.futures.ProcessPoolExecutor(max_workers=500) as executor:
                futures = [executor.submit(single_port_scan, i) for i in range(5000)]

        elif scan_type == 3:
            DEFAULT_TIMEOUT = 2
            print("\n==Initiating All Port Scanning==\n")
            # for i in tqdm(range(65535)):
            #     single_port_scan(i)

            with concurrent.futures.ProcessPoolExecutor(max_workers=500) as executor:
                futures = [executor.submit(single_port_scan, i) for i in range(65535)]

        else:
            sys.exit("Invalid Scan Type")
    except:
        sys.exit("Exiting")



def single_port_scan(i):

    con = check_port(host, i)
    if con == True:
        print("Port {}: 	 Open".format(i))
        success_list.append("Port {}: 	 Open".format(i))
        # print("Success list",success_list)


if __name__ == "__main__":
    global host
    well_known = [1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53, 69, 70, 79, 80, 103, 108, 109, 110, 115, 118,
                  119, 137, 139, 143, 150, 156, 161, 179, 190,
                  194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080]
    success_list = list()

    initiating()
    print()
    print()
    start = timer()
    try:
        IP = socket.gethostbyname(host)
        print("IP : ", IP)
        print("Scanning -", host)
    except:
        sys.exit("Couldn't resolve IP")

    print()
    print()

    scanning()

    print("")
    print()
    print("Scanning Completed")
    print()
    # if len(success_list)>0:
    #     for i in success_list:
    #         print(i)
    # else:
    #     print("No open ports found")
    print('Took: %.2f seconds.' % (timer() - start))