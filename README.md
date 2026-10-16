# testpayload

A minimal PS5 payload built with the [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk).
It prints a message and shows a notification on screen.

## Build

Install the SDK, then:

```sh
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make
```

## Run

For a console that already runs an ELF loader (default port 9021):

```sh
export PS5_HOST=<console-ip>
export PS5_PORT=9021
make test
```
