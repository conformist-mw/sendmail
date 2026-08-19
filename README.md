# sendmail to telegram bot

[![Builder](https://github.com/conformist-mw/sendmail/actions/workflows/build.yaml/badge.svg)](https://github.com/conformist-mw/sendmail/actions/workflows/build.yaml)

![New Project(1)](https://user-images.githubusercontent.com/13550539/142740382-147f4b3f-d579-426d-9f36-74e38d24c126.png)

### Description

Traditionally email has been used in Linux to communication or inform the user about some kind of problems. In the current environment it is rather difficult to set up a good mail server so that outgoing mail does not end up in spam. 

This project exists to simplify the notification to the end user. In Linux all programs that want to send an email somewhere always use `/usr/sbin/sendmail`. This project implements that command and also provides a mail-transport-agent package so that it is possible to send mails manually e.g. with the `mailutils` or `bsd-mailx` packages (these require that an MTA is installed, usually Postfix/Exim/Sendmail and so on).

### Installation

There are two ways to install it:

1. Recommended
    - go to [Releases](https://github.com/conformist-mw/sendmail/releases) and download the current
      `tg-sendmail_x.x.x_<arch>.deb` for your architecture (`amd64`, `arm64` or `armhf`)
    - install:
    ```shell
    sudo apt install ./tg-sendmail_x.x.x_amd64.deb
    ```
    - optionally (to send mails as user):
   ```shell
    sudo apt install bsd-mailx  # or mailutils
    ```

2. Manual
    - clone this repo
    - build and copy files to their destinations:
   ```shell
    make build
    sudo cp sendmail /usr/sbin/sendmail
    sudo cp sendmail.yaml.example /etc/tg-sendmail.yaml  # fill values
    sudo touch /var/log/tg-sendmail.log
    sudo chmod 666 /var/log/tg-sendmail.log
   ```

The installed package contains a compiled static binary, so Go is only needed
to build it, never on the machine where it is installed.

### Build package yourself

```shell
git clone https://github.com/conformist-mw/sendmail
cd sendmail
sudo apt install devscripts debhelper dh-exec dh-make golang-go
debuild --no-lintian
```

Dependencies are vendored, so the build needs no network access. To build for
another architecture:

```shell
dpkg-buildpackage --host-arch arm64 --build=any -d -us -uc
```

### Development

```shell
make test   # run the tests
make lint   # gofmt and go vet
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

Find the chat id to configure:

```shell
$ sendmail --get-updates
```

This asks Telegram for the messages sent to the bot. It fails with a `409
Conflict` when a webhook is registered for the same bot (for example when the
bot is shared with Home Assistant), because Telegram allows only one of the two
at a time. In that case take the chat id from the service that owns the
webhook, or from a bot such as `@userinfobot`.

Send files (see telegram bot api [limitations](https://core.telegram.org/bots/api#sending-files)):

```shell
$ sendmail --send-file /var/log/tg-sendmail.log
```

![Sent file](https://user-images.githubusercontent.com/13550539/142765226-ba5d978f-a9af-4c70-bb7f-935c2e3f2f8f.png)

