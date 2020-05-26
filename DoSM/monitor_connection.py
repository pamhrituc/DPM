import psutil

def remote_ips():
    '''
    Returns the list of IPs for current active connections
    '''

    remote_ips = []

    for process in psutil.process_iter():
        try:
            connections = process.get_connections(kind = 'inet')
        except psutil.AccessDenied or psutil.NoSuchProcess:
            pass
        else:
            for connection in connections:
                if connection.remote_address and connection.remote_address[0] not in remote_ips:
                    remote_ips.append(connection.remote_address[0])

    return remote_ips
