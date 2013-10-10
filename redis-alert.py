import ConfigParser
import argparse
import email
import logging
import smtplib
import redis
import socket

__author__ = 'ldalamagas'

config = {}

# Configure the logger
logger = logging.getLogger("backup")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("REDIS-ALERT[%(process)d] %(levelname)s: %(message)s")
syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
stream_handler = logging.StreamHandler()
syslog_handler.setFormatter(fmt=formatter)
logger.addHandler(syslog_handler)
logger.addHandler(stream_handler)


def arguments():
    parser = argparse.ArgumentParser(description="Redis Alert")
    parser.add_argument("--config", default="redis-alert.cfg", help="Path to the configuration file")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=6379)
    return parser.parse_args()


def read_config(configuration_file, config):
    logger.info("running redis-alert with [%s] configuration", configuration_file)
    cp = ConfigParser.ConfigParser()
    cp.readfp(open(configuration_file))

    # General backup configuration
    config["backup_items"] = (cp.get("backup", "items")).split(",")
    config["backup_prefix"] = cp.get("backup", "prefix")
    config["backup_suffix"] = cp.get("backup", "suffix")
    config["retention_enabled"] = cp.getboolean("backup", "retention_enabled")
    config["retention_period"] = cp.getint("backup", "retention")
    config["tmp_dir"] = cp.get("backup", "temp_storage")

    # MySQL
    config["db_enabled"] = cp.getboolean("mysql", "enabled")
    config["db_names"] = (cp.get("mysql", "names")).split(",")
    config["db_host"] = cp.get("mysql", "host")
    config["db_user"] = cp.get("mysql", "user")
    config["db_password"] = cp.get("mysql", "password")

    # Remote Storage
    config["ftp_host"] = cp.get("ftp", "host")
    config["ftp_dir"] = cp.get("ftp", "dir")
    config["ftp_user"] = cp.get("ftp", "user")
    config["ftp_password"] = cp.get("ftp", "password")

    # Mail Notifications
    config["smtp_enabled"] = cp.getboolean("smtp", "enabled")
    config["smtp_server"] = cp.get("smtp", "server")
    config["smtp_from_address"] = cp.get("smtp", "from")
    config["smtp_to_addresses"] = (cp.get("smtp", "to")).split(",")
    config["smtp_user"] = cp.get("smtp", "user")
    config["smtp_password"] = cp.get("smtp", "password")


def send_mail(message):
    smtp = None
    try:
        msg = email.MIMEText(message)
        msg['Subject'] = 'Error while backing up [%s]' % socket.gethostname()
        msg['From'] = config["smtp_from_address"]
        msg['Reply-To'] = config["smtp_from_address"]
        msg['To'] = config["smtp_to_address"]

        smtp = smtplib.SMTP(config["smtp_server"])
        smtp.starttls()
        smtp.login(config["smtp_user"], config["smtp_password"])
        smtp.sendmail(config["smtp_from_address"], config["smtp_to_address"], msg.as_string())
    except email.errors.MessageError:
        logger.error("Error trying to notify recipients")
    except email.SMTPAuthenticationError:
        logger.error("Error trying to notify recipients, please check your smtp credentials")
    finally:
        smtp.quit()

if __name__ == '__main__':
    arguments = arguments()
    r = redis.Redis(host=arguments.host, port=arguments.port)
    um = 0

    used_memory = r.info()['used_memory']   # In Bytes
    used_memory_in_mb = used_memory/1024.0/1024.0
    print "{0:.2f}".format(used_memory_in_mb)