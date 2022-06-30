import logging
from termcolor import colored

# logging code. This is used for us to debug in case of an error. You can see the logs through kubectl logs <pod_name>
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

def log_message(message):
	logger.info(colored(message, "cyan"))

def log_vulnerability(message):
	logger.critical(colored(message, "red"))