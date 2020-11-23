from socket import gethostname


def get_queue_name(join_symbol: str, data_type: str, suffix: str = gethostname()):
    """
    Returns a queue name accroding to the desired pattern.
    @param join_symbol The symbol to use when concatenating the name
    @param data_type The type of data that goes through the queue (e.g., "intel")
    @param suffix A suffix to append to the name. Default: the hostname
    """
    return join_symbol.join(["threatbus", data_type, suffix])


def get_exchange_name(join_symbol: str, data_type: str):
    """
    Returns an exchange name accroding to the desired pattern.
    @param join_symbol The symbol to use when concatenating the name
    @param data_type The type of data that goes through the queue (e.g., "intel")
    @param suffix A suffix to append to the name. Default: the hostname
    """
    return join_symbol.join(["threatbus", data_type])
