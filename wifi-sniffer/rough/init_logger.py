def init_info_logger():
    logging.basicConfig(filename='error.log', level=logging.ERROR, format='%(asctime)s %(levelname)s:%(message)s') # errors
    # print statements
    info_logger = logging.getLogger('info_logger')
    info_logger.setLevel(logging.INFO)
    # file handler
    file_handler = logging.FileHandler('info.log')
    file_handler.setLevel(logging.INFO)
    # formatter
    log_formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
    file_handler.setFormatter(log_formatter) # configure file_handler
    info_logger.addHandler(file_handler)

    return info_logger


