# aMule EC Protocol - Node.js Implementation

This project provides a Node.js implementation of the aMule External Connections (EC) Protocol based on the [aMule EC Protocol HOWTO](https://wiki.amule.org/wiki/EC_Protocol_HOWTO).

Tested with aMule 3.0.1, and with master builds past it for the commands that
only exist there. Older cores, back to 2.3.3, keep working: a command the daemon
may not know is gated on the capability it advertises at connect time and is
never sent otherwise, and the rest degrade to the older reply.

## Features

- Communicate with aMule via EC protocol
- Send commands and receive status or transfer info

### Installation

```bash
git clone https://github.com/got3nks/amule-ec-node.git
cd amule-ec-node
npm install
```

### Example Usage

```bash
npm start
```

See [`examples/test.js`](examples/test.js) for usage.

## License

MIT
