import ConfigParser
import argparse
import email
import logging
from logging import StreamHandler
from logging.handlers import SysLogHandler
import smtplib
import redis
from email.mime.text import MIMEText
import pprint

__author__ = 'ldalamagas'

config = {}

# Configure the logger
logger = logging.getLogger("backup")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("REDIS-ALERT[%(process)d] %(levelname)s: %(message)s")
syslog_handler = SysLogHandler(address="/dev/log")
stream_handler = StreamHandler()
syslog_handler.setFormatter(fmt=formatter)
logger.addHandler(syslog_handler)
logger.addHandler(stream_handler)


def arguments():
    parser = argparse.ArgumentParser(description="Redis Alert")
    parser.add_argument("-c", "--config", default="redis-alert.cfg", help="Path to the configuration file")
    return parser.parse_args()


def read_config(configuration_file):
    global config
    logger.info("running redis-alert with [%s] configuration", configuration_file)
    cp = ConfigParser.ConfigParser()
    cp.readfp(open(configuration_file))
    config["redis_host"] = cp.get("redis", "host")
    config["redis_port"] = cp.getint("redis", "port")
    config["redis_threshold"] = cp.getfloat("redis", "threshold")

    # Mail Notifications
    config["smtp_enabled"] = cp.getboolean("smtp", "enabled")
    config["smtp_server"] = cp.get("smtp", "server")
    config["smtp_from_address"] = cp.get("smtp", "from")
    config["smtp_to_addresses"] = (cp.get("smtp", "to")).split(",")
    config["smtp_user"] = cp.get("smtp", "user")
    config["smtp_password"] = cp.get("smtp", "password")


def send_mail(subject, message):
    smtp = None
    try:
        msg = MIMEText(message, 'html')
        msg['Subject'] = subject
        msg['From'] = config["smtp_from_address"]
        msg['Reply-To'] = config["smtp_from_address"]
        msg['To'] = ",".join(config["smtp_to_addresses"])

        smtp = smtplib.SMTP(config["smtp_server"])
        smtp.starttls()
        smtp.login(config["smtp_user"], config["smtp_password"])
        smtp.sendmail(config["smtp_from_address"], config["smtp_to_addresses"], msg.as_string())
    except email.errors.MessageError:
        logger.error("Error trying to notify recipients")
    except smtplib.SMTPAuthenticationError:
        logger.error("Error trying to notify recipients, please check your smtp credentials")
    finally:
        if smtp:
            smtp.quit()

if __name__ == '__main__':
    arguments = arguments()

    try:
        read_config(arguments.config)
    except ConfigParser.Error as error:
        logger.error("Error while reading configuration: %s", error.message)
        exit(1)
    except IOError as error:
        logger.error("Error while reading configuration: %s", error.strerror)
        exit(1)

    r = redis.Redis(host=config["redis_host"], port=config["redis_port"])
    um = 0
    used_memory = 0
    try:
        used_memory = r.info()['used_memory']           # In Bytes
    except redis.RedisError as error:
        message = "Error while communicating with redis: %s" % error.message
        logger.error(message)
        send_mail("Redis Alert Error", message)
        exit(1)

    used_memory_in_mb = used_memory/1024.0/1024.0   # In MBytes

    if used_memory_in_mb > config["redis_threshold"]:
        message = "Redis server memory consumption has reached to " \
                  "[%.2f]MB, the configured threshold is [%.2f]MB" % (used_memory_in_mb, config["redis_threshold"])
        logger.error(message)

        if config["smtp_enabled"]:
            subject = "Redis Memory Threshold exceeded on [%s]" % config["redis_host"]
            full_info = r.info()
            html = """
            <html>
              <head></head>
              <body>
                <h1>Warning</h1>
                <p>
                    Redis server memory consumption has reached to
                    <strong>[%.2f]MB</strong>, the configured threshold is <strong>[%.2f]MB</strong>
                </p>
                <h3>Redis Info</h3>
                <pre>%s</pre>
              </body>
            </html>
            """ % (used_memory_in_mb, config["redis_threshold"], pprint.pformat(full_info))
            send_mail(subject, html)