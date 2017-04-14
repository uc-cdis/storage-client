from cleversafe import CleversafeClient


def get_client(config=None, backend=None):
    try:
        # if backend == 'cleversafe':
        #     return CleversafeClient(config)
        # if backend == 'ceph':
        #     raise NotImplementedError()
        clients = {'cleversafe': CleversafeClient}
        return clients[backend](config)
    except KeyError as ex:
        raise NotImplementedError("The input storage is currently not supported!: {0}".format(ex))
