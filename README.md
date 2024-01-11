# sendmail to telegram bot

[![Builder](https://github.com/conformist-mw/sendmail/actions/workflows/build.yaml/badge.svg)](https://github.com/conformist-mw/sendmail/actions/workflows/build.yaml)

![New Project(1)](https://user-images.githubusercontent.com/13550539/142740382-147f4b3f-d579-426d-9f36-74e38d24c126.png)

### Description

Traditionally email has been used in Linux to communication or inform the user about some kind of problems. In the current environment it is rather difficult to set up a good mail server so that outgoing mail does not end up in spam. 

This project exists to simplify the notification to the end user. In Linux all programs that want to send an email somewhere always use `/usr/sbin/sendmail`. This project implements that command and also provides a mail-transport-agent package so that it is possible to send mails manually e.g. with the `mailutils` or `bsd-mailx` packages (these require that an MTA is installed, usually Postfix/Exim/Sendmail and so on).

### Installation

There are two ways to install it:

1. Recommended
    - go to [Releases](https://github.com/conformist-mw/sendmail/releases) and download current `tg-sendmail_x.x.x_all.deb`
    - install:
    ```shell
    sudo apt install ./tg-sendmail_x.x.x_all.deb
    ```
    - optionally (to send mails as user):
   ```shell
    sudo apt install bsd-mailx  # or mailutils
    ```

2. Manual
    - clone this repo
    - copy files to their destinations:
   ```shell
    sudo cp src/sendmail.py /usr/sbin/sendmail
    sudo cp src/sendmail.ini /etc/tg-sendmail.ini  # fill values
    sudo touch /var/log/tg-sendmail.log
    sudo chmod 666 /var/log/tg-sendmail.log
   ```

### Build package yourself

```shell
git clone https://github.com/conformist-mw/sendmail
cd sendmail
sudo apt install devscripts debhelper dh-exec dh-make dh-python
debuild --no-lintian
```

### Usage

After installation, you can check how it works for cron tasks, which notify the user by email in case of an error:

- add a knowingly erroneous command to the cron:

```shell
* * * * * /usr/bin/non-existent-command
```
![Failed cron job](https://user-images.githubusercontent.com/13550539/142764635-af564b8e-532e-4981-a6e2-d4974a8d1f79.png)

Send emails:

```shell
$ echo 'Mail from the server' | mail -s 'Test subject' oleg.smedyuk@gmail.com
```
![Sent email](https://user-images.githubusercontent.com/13550539/142764816-0109b90f-cef7-4282-8ca1-d81a9024335d.png)

Send files (see telegram bot api [limitations](https://core.telegram.org/bots/api#sending-files)):

```shell
$ sendmail --send-file /var/log/tg-sendmail.log
```

![Sent file](https://user-images.githubusercontent.com/13550539/142765226-ba5d978f-a9af-4c70-bb7f-935c2e3f2f8f.png)

