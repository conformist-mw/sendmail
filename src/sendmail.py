#!/usr/bin/python3
import argparse
import configparser
import json
import logging
import sys
import urllib.error
from email.parser import Parser
from email.utils import parseaddr
from html import escape
from urllib import request

config = configparser.ConfigParser()
config.read('tg-sendmail.ini')
main_config = config['main']
telegram_config = config['telegram']

logging.basicConfig(
    level=main_config['log_level'].upper(),
    filename=main_config['log_path'],
    filemode='a',
    format='{asctime} {name} - {levelname} - {message}',
    style='{',
)
logger = logging.getLogger('sendmail')


def get_updates(token):  # noqa: C901
    url = f'https://api.telegram.org/bot{token}/getUpdates'
    try:
        response = request.urlopen(url).read().decode()
    except urllib.error.URLError as error:
        logger.error('get updates error. URL: %s Error: %s', url, error)
        return
    logger.debug('get updates response: %s', response)
    try:
        updates = json.loads(response)
    except json.JSONDecodeError as error:
        logger.error('get updates json decode error: %s', error)
        return
    if not updates['ok']:
        logger.error('get updates response is not ok')
        return
    messages = updates['result']
    if not messages:
        warning_message = 'No updates. Try to send some messages to the bot'
        logger.warning(warning_message)
        sys.stdout.write(warning_message)
        return
    for message in messages:
        logger.debug('get updates message: %s', json.dumps(message))
        chat_id = message['message']['chat']['id']
        username = message['message']['chat']['username']
        log_string = f'Chat Id: {chat_id}. Username: {username}'
        logger.info('get updates data: %s', log_string)
        sys.stdout.write(log_string)


def generate_full_name(full_name, address):
    full_address = address
    if full_name:
        full_address = f'{full_name} <{address}>'
    return full_address


def parse_args():
    parser = argparse.ArgumentParser(
        description='Drop-in replacement for any MTA sendmail',
    )
    parser.add_argument(
        '--get-updates',
        action='store_true',
        help='Run getUpdates method with bot token to achieve chat_id',
    )
    parser.add_argument('-F', help='Set the full name of the sender.')
    parser.add_argument(
        '-f',
        help='Sets the name of the ''from'' person (i.e., the envelope sender'
             ' of the mail). This address may also be used in the From: header'
             ' if that header is missing during initial submission.',
    )
    parser.add_argument(
        '-t', action='store_true', help='Read message for recipients.',
    )
    parser.add_argument('remains', nargs='*', help='Should be an email')
    return parser.parse_known_args()


def prepare_email(sender_name, sender_address, remains, parse_to_header):
    email = Parser().parse(sys.stdin)
    if not parse_to_header and not email['to'] and remains:
        for arg in remains:
            full_name, address = parseaddr(arg)
            # https://datatracker.ietf.org/doc/html/rfc822#section-6
            # due to this rfc we actually don't care about validness of an
            # address, just put any of given information into `To:` if it is
            # empty
            email.add_header('To', generate_full_name(full_name, address))
    if not email['from'] and sender_address:
        email.add_header(
            'From',
            generate_full_name(sender_name, sender_address),
        )
    return email


def generate_message(email):
    message = []
    for header, value in email.items():
        message.append(f'<i>{escape(header)}:</i> <b>{escape(value)}</b>')
    message.append('\n')
    message.append(f'<pre>{escape(email.get_payload())}</pre>')
    return '\n'.join(message)


def send(message, token, chat_id):
    url = f'https://api.telegram.org/bot{token}/sendMessage'
    payload = {
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'HTML',
    }
    logger.debug('Send payload: %s', json.dumps(payload))
    headers = {
        'Content-Type': 'application/json',
    }
    data = json.dumps(payload).encode()
    req = request.Request(url, data, headers)
    with urllib.request.urlopen(req) as response:
        res = response.read()
        logger.debug('Response: %s', res.decode())


if __name__ == '__main__':
    chat_id = telegram_config['chat_id']
    bot_token = telegram_config['bot_token']
    args, unknown_args = parse_args()
    if args.get_updates:
        # used to get know chat_id
        get_updates(bot_token)
        exit()
    email = prepare_email(args.F, args.f, args.remains, args.t)
    logger.debug('Prepared email: %s', email.as_string())
    message = generate_message(email)
    logger.debug('Prepared message: %s', message)
    send(message, bot_token, chat_id)
