import psutil

def remote_ips():
    '''
    Returns the list of IPs for current active connections
    '''

    remote_ips = []

    for process in psutil.process_iter():
        try:
            connections = process.connections(kind = 'inet')
        except psutil.AccessDenied or psutil.NoSuchProcess:
            pass
        else:
            for connection in connections:
                if connection[4] != ():
                    remote_ips.append(connection[4][0][connection[4][0].rfind(':') + 1:])
                    remote_ips = list(set(remote_ips))

    return remote_ips

while True:
    print(remote_ips())
