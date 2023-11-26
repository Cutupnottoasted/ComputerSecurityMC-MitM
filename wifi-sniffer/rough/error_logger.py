
def error_logger(error=None):
    error_msg = f'{datetime.now()} - An error occurred: {error}\n{traceback.format_exc()}'
    logging.error(error_msg)