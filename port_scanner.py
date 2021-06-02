import argparse
import multiprocessing
from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.ntp import NTPHeader


RESULTS = multiprocessing.Queue()
LOCK_PRINTING = Lock()


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('host', help='адресс хоста')
    parser.add_argument('range', help='интервал портов, задаётся через дефис')

    return parser.parse_args()


def check_port(ip, port):
    check_tcp_res = check_port_tcp(ip, port)
    if check_tcp_res[0]:
        with LOCK_PRINTING:
            if check_tcp_res[1] != '':
                RESULTS.put((port, 'TCP', check_tcp_res[1]))
            else:
                RESULTS.put((port, 'TCP', None))

    check_udp_res = check_port_udp(ip, port)
    if check_udp_res[0]:
        with LOCK_PRINTING:
            if check_udp_res[1] != '':
                RESULTS.put((port, 'UDP', check_udp_res[1]))
            else:
                RESULTS.put((port, 'UDP', None))


def check_port_tcp(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_tcp:
        socket_tcp.settimeout(1)
        connected = socket_tcp.connect_ex((ip, port))
        if connected == 0:
            return True, check_protocol_on_port(socket_tcp)
        return False, ''


def check_port_udp(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket_udp:
        socket_udp.settimeout(1)
        connected = socket_udp.connect_ex((ip, port))
        if connected == 0:
            return True, check_protocol_on_port(socket_udp)
        return False, ''


def check_protocol_on_port(_socket):
    try:
        _socket.send(HTTPRequest().build())
        pkt_response = _socket.recv(1024)

        if HTTPResponse(_pkt=pkt_response).Status_Code != 0:
            return 'http'
    except:
        pass

    try:
        _socket.send('HELO'.encode())
        pkt_response = _socket.recv(1024)
        data = pkt_response.decode()

        int(data[:3])
        return 'smtp'
    except:
        pass

    try:
        _socket.send('USER mrose'.encode())
        pkt_response = _socket.recv(1024)
        data = pkt_response.decode()

        if any(['+OK' in data, '-ERR' in data]):
            return 'pop3'
    except:
        pass

    try:
        _socket.send(DNS(qr=0, qd=DNSQR()).build())
        pkt_response = _socket.recv(1024)

        if DNS(_pkt=pkt_response).qr == 1:
            return 'dns'
    except:
        pass

    try:
        _socket.send(NTPHeader().build())
        pkt_response = _socket.recv(1024)

        if NTPHeader(_pkt=pkt_response).recv != 0:
            return 'ntp'
    except:
        pass

    return ''


def main():
    def print_waiting():
        positions = ['/', '-', '\\', '|']
        i = 0
        while flag_waiting:
            print(f'\rProcessing: {positions[i]}', end='')
            i = (i + 1) % len(positions)
            time.sleep(0.25)

    logging.getLogger('scapy').setLevel(logging.ERROR)

    args = parse_args()

    host = args.host
    flag_domain = False
    if host.lower() == 'localhost':
        host = socket.gethostbyaddr(socket.gethostname())[2][0]
    else:
        match = re.findall(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)

        if len(match) != 0:
            pass
        else:
            try:
                host = socket.gethostbyaddr(host)[2][0]
                flag_domain = True
            except Exception:
                print(f'Exception! Invalid address!')
                return

    print(f'Port scanning of {host}' +
          (f' [{args.host}]' if flag_domain else '') + ':')

    start, end = map(int, args.range.split('-'))
    threads = list()

    flag_waiting = True
    thread_print = threading.Thread(
        target=print_waiting)
    thread_print.start()

    for i in range((end - start) // 1000 + 1):
        _start = start + i * 1000
        _end = min(_start + 1000, end)

        for port in range(_start, _end + 1):
            thread = threading.Thread(
                target=check_port,
                args=(host, port))
            threads.append(thread)

            while True:
                try:
                    thread.start()
                    break
                except RuntimeError:
                    pass

        for thread in threads:
            thread.join()

    RESULTS.put(None)
    flag_waiting = False
    thread_print.join()

    _dict = {}
    while True:
        obj = RESULTS.get()
        if obj is None:
            break
        port, pr, protocol = obj
        if pr not in _dict.keys():
            _dict[pr] = {}
        _dict[pr][port] = protocol

    _list = list(_dict.items())
    if len(_list) != 2:
        temp = {'TCP', 'UDP'}
        temp2 = set()
        for pr, _ in _list:
            if pr not in temp2:
                temp2.add(pr)
        for pr in temp.difference(temp2):
            _list.append((pr, dict()))

    print('\r', end='')
    for pr, values in _list:
        ports = []
        values = {k: v for k, v in sorted(list(values.items()),
                                          key=lambda x: x[0])}
        for k, v in values.items():
            if v is not None:
                ports.append((k, k, v, False))
            else:
                if len(ports) == 0:
                    ports.append((k, k, v, True))
                elif ports[-1][-1] and ports[-1][1] == k - 1:
                    ports[-1] = (ports[-1][0], k, ports[-1][2], True)
                else:
                    ports.append((k, k, v, True))

        res = []
        for p in ports:
            suffix = f'({p[-2]})' if p[-2] is not None else ''
            if p[-1]:
                if p[0] != p[1]:
                    res.append(f'{p[0]}-{p[1]}{suffix}')
                else:
                    res.append(f'{p[0]}{suffix}')
            else:
                res.append(f'{p[0]}{suffix}')

        if len(res) != 0:
            print(f'[{pr}] Opened ports: ' + ', '.join(res))
        else:
            print(f'[{pr}] No opened ports')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
