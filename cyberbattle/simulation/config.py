import sys
import logging
import os
from dotenv import load_dotenv
import datetime
from torch.utils.tensorboard import SummaryWriter

load_dotenv()


class LoggerWriter:
    def __init__(self, logger, level):
        self.logger = logger
        self.level = level

    def write(self, message):
        if message != '\n':
            self.logger.log(self.level, message)

    def flush(self):
        # create a flush method so things can be flushed when
        # the system wants to. Not sure if simply 'printing'
        # sys.stderr is the correct way to do it, but it seemed
        # to work properly for me.
        # self.level(sys.stderr)
        pass


class StreamToLogger(object):
    """
    Fake file-like stream object that redirects writes to a logger instance.
    """

    def __init__(self, logger, level):
        self.logger = logger
        self.level = level
        self.linebuf = ''

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self.logger.log(self.level, line.rstrip())

    def flush(self):
        pass


class Configuration():
    def __init__(self):
        self.LOGGER_NAME = "General"
        self.logger = logging.getLogger(self.LOGGER_NAME)
        log_dir = '/logs/exper/' + "dummy_log_folder"
        # convert the datetime object to string of specific format
        datetime_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_results = os.getenv("LOG_RESULTS", 'False').lower() in ('true', '1', 't')
        gymid = os.getenv("GYMID", 'CyberBattleTinyMicro-v0')
        self.log_dir = os.path.join(log_dir, gymid, datetime_str)
        self.summary_dir = None
        self.log_level = os.getenv("LOG_LEVEL", "info")
        self.writer = None
        self.honeytokens_on = {"HT1_v2tov1": True, "HT2_phonebook": True, "HT3_state": True, "HT4_cloudactivedefense": True}
        if type(self.honeytokens_on) == str:
            self.honeytokens_on = {{ht_include_tuple.split(':')[0].strip(): ht_include_tuple.split(':')[1].strip().lower() in ['true', 'True']}
                                   for ht_include_tuple in os.getenv('HONEYTOKENS_ON')[1:-1].split(',')}

    def update_globals(self, log_dir: str, gymid: str, log_level: str, log_results: bool, honeytokens_on: dict = {}) -> None:
        self.log_dir, self.gymid, self.log_level, self.log_results, self.honeytokens_on = log_dir, gymid, log_level, log_results, honeytokens_on

    def update_logger(self):
        # if len(logging.getLogger().handlers):
        #     return logging.getLogger(LOGGER_NAME)

        # log_results = os.getenv("LOG_RESULTS", 'False').lower() in ('true', '1', 't')

        log_level_dict = {"info": logging.INFO, "error": logging.ERROR, "debug": logging.DEBUG, "warn": logging.WARN, }
        # logging.basicConfig(level=log_level_dict[os.environ["LOG_LEVEL"]],
        #                     format="[%(asctime)s] %(levelname)s: %(message)s", datefmt='%Y-%m-%d %H:%M:%S',)
        # filename=os.path.join(log_dir, 'logfile.txt'),
        # filemode='a')
        # handlers = [logging.StreamHandler(sys.stderr), logging.StreamHandler(sys.stdout)])

        # if logging.getLogger("General").hasHandlers()recon
        #     return logging.getLogger("General")
        # self.logger = logging.getLogger(LOGGER_NAME)

        self.logger.setLevel(log_level_dict[self.log_level])

        # self.logger.disabled = True
        # handler = logging.StreamHandler(sys.stdout)
        # formatter = logging.Formatter(fmt="[%(asctime)s] %(levelname)s: %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
        # handler.setFormatter(formatter)
        # self.logger.addHandler(handler)

        if self.log_results:
            # os.makedirs(self.log_dir, exist_ok=True)
            sys.stdout = LoggerWriter(self.logger, log_level_dict[self.log_level])  # logging.INFO)
            # sys.stderr = LoggerWriter(self.logger, logging.ERROR)
            handler = logging.FileHandler(os.path.join(self.log_dir, 'logfile.log'))
            formatter = logging.Formatter(fmt="[%(asctime)s] %(levelname)s: %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
            handler.setFormatter(formatter)
            handler_memory = handler  # logging.handlers.MemoryHandler(10**2, target=handler)
            self.logger.addHandler(handler_memory)
        else:
            pass
            # self.logger.setLevel(logging.CRITICAL)
            # self.logger.propagate = True  # do not pass log_messages to the higher hierarchy logger, i.e. do not right to stdout
            # else:
            #     sys.stdout = LoggerWriter(None, None)
            # lhStdout = logger.handlers[0]  # stdout is the only handler initially
            # logger.removeHandler(lhStdout)
        if self.log_results:
            self.summary_dir = os.path.join(self.log_dir, 'training/' if 'dql' in self.log_dir else '')
            os.makedirs(self.summary_dir, exist_ok=True)
        self.writer = WriterWrapper(log_results=self.log_results, log_dir=self.summary_dir)


class WriterWrapper(SummaryWriter):

    def __init__(self, log_results: bool, **kwargs):
        self.log_results = log_results
        if log_results:
            super().__init__(**kwargs)

    def empty_method(self, *args, **kwargs):
        pass

    def __getattribute__(self, attr):
        if hasattr(SummaryWriter, attr):
            if not self.log_results and callable(getattr(SummaryWriter, attr)):  # callable(method)
                # print("No writer")
                return super().__getattribute__("empty_method")
            return super().__getattribute__(attr)
        return object.__getattribute__(self, attr)


configuration = Configuration()
logger, writer = configuration.logger, configuration.writer  # None, None
