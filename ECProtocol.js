"use strict";

const util = require('util')
const net = require("net");
const crypto = require("crypto");
const {
  EC_OPCODES,
  EC_TAGS,
  EC_TAG_TYPES,
  PROTOCOL_VERSION
} = require("./ECDefs");

const DEBUG = false;

class ECProtocol {
  constructor(host = HOST, port = PORT, password = PASSWORD) {
    this.host = host;
    this.port = port;
    this.password = password;
    this.socket = null;
    this.bufferedData = Buffer.alloc(0);
    this.manualClose = false;
    this.reconnecting = false;
    this.pendingRequests = [];
  }

  async connect() {
    return new Promise((resolve, reject) => {
      this.socket = new net.Socket();
      
      const onError = (err) => reject(err);
      this.socket.once("error", onError);
      
      this.socket.connect(this.port, this.host, () => {
        if(DEBUG) console.log("Connected to aMule EC interface");
        this.socket.removeListener("error", onError);
        this.setupSocketListeners();
        resolve();
      });
    });
  }

  setupSocketListeners() {
    this.socket.on("close", async () => {
      this.rejectPendingRequests(new Error("Connection closed"));
      
      if(this.manualClose === false && !this.reconnecting) {
        console.warn("[ECProtocol] Connection closed. Attempting reconnect...");
        await this.reconnect();
      }
    });

    this.socket.on("error", async (err) => {
      console.error("[ECProtocol] Socket error:", err.message);
      
      this.rejectPendingRequests(err);
      
      if (!this.socket.destroyed) this.socket.destroy();
      
      if (!this.reconnecting) {
        await this.reconnect();
      }
    });
  }

  rejectPendingRequests(error) {
    while (this.pendingRequests.length > 0) {
      const request = this.pendingRequests.shift();
      if (this.socket) {
        this.socket.removeListener("data", request.onData);
      }
      request.reject(error);
    }
  }

  close() {
    if (this.socket) {
      this.manualClose = true;
      this.rejectPendingRequests(new Error("Connection manually closed"));
      this.socket.end();
      this.socket.destroy();
      this.socket = null;
    }
  }

  async reconnect(retries = 6, delayMs = 10000) {
    if (this.reconnecting) return;
    this.reconnecting = true;
    this.manualClose = false;
    
    if (this.socket) {
      this.rejectPendingRequests(new Error("Reconnecting"));
      this.socket.removeAllListeners();
      if (!this.socket.destroyed) {
        this.socket.destroy();
      }
      this.socket = null;
    }
    
    for (let i = 0; i < retries; i++) {
      try {
        if(DEBUG) console.log(`[ECProtocol] Reconnection attempt ${i + 1}...`);
        await this.connect();
        if(DEBUG) console.log(`[ECProtocol] Authentication attempt ${i + 1}...`);
        await this.authenticate();
        if(DEBUG) console.log("[ECProtocol] Reconnected and authenticated successfully.");
        this.reconnecting = false;
        return;
      } catch (err) {
        console.warn(`[ECProtocol] Reconnect attempt ${i + 1} failed:`, err.message);
        if (i < retries - 1) {
          await new Promise(r => setTimeout(r, delayMs));
        }
      }
    }
    
    this.reconnecting = false;
    throw new Error("[ECProtocol] Unable to reconnect after multiple attempts.");
  }

  /*
   * Build a tag.
   */
  createTag(tagId, tagType, value, children = []) {
    if(tagType===undefined) throw new Error('Called createTag with undefined tagType');
    
    // Determine if children exist and mark the tagId accordingly (lowest bit set if there are children)
    const hasChildren = Array.isArray(children) && children.length > 0;
    // Shift tagId one bit to the left so that the lowest bit is free:
    let encodedTagId = tagId << 1;
    if (hasChildren) encodedTagId |= 1;

    // Build children block first
    let childrenContent = Buffer.alloc(0);
    if (hasChildren) {
      const countBuf = Buffer.alloc(2);
      countBuf.writeUInt16BE(children.length, 0);
      const childBuffers = children.map(c =>
        this.createTag(c.tagId, c.tagType, c.value, c.children || [])
      );
      childrenContent = Buffer.concat([countBuf, ...childBuffers]);
    }

    // Now build valueBuffer (only if the tag has its own value)
    let valueBuffer = Buffer.alloc(0);
    if (!hasChildren || value !== undefined) {
      switch (tagType) {
        case EC_TAG_TYPES.EC_TAGTYPE_STRING:
          // For strings, we use UTF-8 with a terminating null byte.
          valueBuffer = Buffer.from(value + "\0", "utf8");
          break;
        case EC_TAG_TYPES.EC_TAGTYPE_UINT16:
          valueBuffer = Buffer.alloc(2);
          valueBuffer.writeUInt16BE(value, 0);
          break;
        case EC_TAG_TYPES.EC_TAGTYPE_UINT8:
          valueBuffer = Buffer.alloc(1);
          valueBuffer.writeUInt8(value, 0);
          break;
        case EC_TAG_TYPES.EC_TAGTYPE_IPV4:
          const {ip, port} = value;
          const parts = ip.split('.').map(Number);
          valueBuffer = Buffer.alloc(6);

          // IP little-endian
          valueBuffer[0] = parts[0];
          valueBuffer[1] = parts[1];
          valueBuffer[2] = parts[2];
          valueBuffer[3] = parts[3];

          // Port big-endian (network order)
          valueBuffer.writeUInt16BE(port, 4);
          break;
        case EC_TAG_TYPES.EC_TAGTYPE_HASH16:
          if (typeof value === "string") {
            // Assumes hexadecimal string format.
            valueBuffer = Buffer.from(value, "hex");
          } else if (Buffer.isBuffer(value)) {
            valueBuffer = value;
          } else {
            throw new Error("Invalid HASH16 value; expected hex string or Buffer");
          }
          break;
        default:
          throw new Error(`Unsupported tag type: 0x${tagType.toString(16)}`);
      }
    }

    // Total payload length includes children + value
    let payloadLength = childrenContent.length + valueBuffer.length;
    if(hasChildren) payloadLength = payloadLength - 2;

    const header = Buffer.alloc(7);
    header.writeUInt16BE(encodedTagId, 0); // 2 bytes: tag name
    header.writeUInt8(tagType, 2);         // 1 byte: tag type
    header.writeUInt32BE(payloadLength, 3); // 4 bytes: tag payload length

    if(DEBUG) {
      console.log(
        `[TAG] id=0x${tagId.toString(16)} (encoded=0x${encodedTagId.toString(16)}), ` +
        `type=0x${tagType.toString(16)}, hasChildren=${hasChildren}, ` +
        `payloadLength=${payloadLength}`
      );
      if (hasChildren) {
        console.log(`[CHILD TAGS] childrenContent: ${childrenContent.toString("hex")}`);
      }
    }

    return Buffer.concat([header, childrenContent, valueBuffer]);
  }

  /*
   * Build a complete EC packet.
   *
   * The transmission layer starts with a 4-byte flag field (always 0x20 in our plain case)
   * followed by a 4-byte payload length. The application layer then contains:
   *  1-byte opcode, 2-byte tag count, then the tag buffers.
   */
  buildPacket(opcode, tags) {
    // Transmission layer: 4 bytes flags (here fixed to 0x20)
    const flags = Buffer.alloc(4);
    flags.writeUInt32BE(0x20, 0);

    // Build application layer.
    const opcodeBuf = Buffer.from([opcode]);
    const tagCountBuf = Buffer.alloc(2);
    tagCountBuf.writeUInt16BE(tags.length, 0);
    const tagsBuf = Buffer.concat(tags);
    const appData = Buffer.concat([opcodeBuf, tagCountBuf, tagsBuf]);

    // Payload length (application data) is written as 4 bytes.
    const lengthBuf = Buffer.alloc(4);
    lengthBuf.writeUInt32BE(appData.length, 0);

    const packet = Buffer.concat([flags, lengthBuf, appData]);
    if(DEBUG) {
      console.log(`[PACKET STRUCTURE CHECK] flags=${flags.toString('hex')}, length=${lengthBuf.toString('hex')}`);
      console.log(`[PACKET] opcode=0x${opcode.toString(16)}, ` +
                  `tagCount=${tags.length}, ` +
                  `appDataLen=${appData.length}, ` +
                  `totalLen=${packet.length}`);
      console.log(`Final packet hex:\n${packet.toString('hex')}`);
    }
    return packet;
  }

  /*
   * Send a packet to the server and resolve with the parsed reply.
   */
  async sendPacket(opcode, tags = []) {
    if (!this.socket || this.socket.destroyed) {
      console.warn("[ECProtocol] Socket is not connected. Reconnecting...");
      await this.reconnect();
    }

    return new Promise((resolve, reject) => {
      let buffer = Buffer.alloc(0);

      const cleanup = () => {
        const index = this.pendingRequests.findIndex(r => r.onData === onData);
        if (index !== -1) {
          this.pendingRequests.splice(index, 1);
        }
        this.socket.removeListener("data", onData);
      };

      const onData = (data) => {
        try {
          buffer = Buffer.concat([buffer, data]);

          if (buffer.length < 8) {
            return; // Wait until we have at least the header
          }

          const payloadLength = buffer.readUInt32BE(4);
          const expectedLength = payloadLength + 8;

          if (buffer.length < expectedLength) {
            return; // Wait for more data
          }

          cleanup();

          // Process the full packet
          const parsed = this.parsePacket(buffer);
          if(DEBUG) console.log("Received packet", util.inspect(parsed, {showHidden: false, depth: null, colors: true}));

          resolve(parsed);
        } catch (err) {
          cleanup();
          reject(err);
        }
      };

      // Send the packet
      try {
        const packet = this.buildPacket(opcode, tags);
        this.pendingRequests.push({ resolve, reject, onData });
        this.socket.on("data", onData);
        this.socket.write(packet);
      } catch (err) {
        reject(err);
      }
    });
  }

  // Reverse lookup helper
   getKeyByValue(obj, value) {
    return Object.entries(obj).find(([_, v]) => v === value)?.[0] || `UNKNOWN (${value})`;
  }

  /*
   * Parse an incoming packet.
   *
   * The packet starts with:
   * - 4-byte flags,
   * - 4-byte payload length,
   * - Then the application layer: 1-byte opcode, 2-byte tag count, then tags.
   */
  parsePacket(buffer) {
    let offset = 0;
    const flags = buffer.readUInt32BE(offset);
    offset += 4;
    const payloadLength = buffer.readUInt32BE(offset);
    offset += 4;
    const opcode = buffer.readUInt8(offset);
    const opcodeStr=this.getKeyByValue(EC_OPCODES, opcode);
    offset += 1;
    const tagCount = buffer.readUInt16BE(offset);
    offset += 2;

    if(DEBUG) console.log('Processing tags of ',{ flags, payloadLength, opcode, tagCount });

    let tags = [];
    for (let i = 0; i < tagCount; i++) {
      const result = this.readTag(buffer, offset);
      tags.push(result.tag);
      offset = result.newOffset;
    }

    return { flags, payloadLength, opcode, opcodeStr, tagCount, tags };
  }

  /*
   * Recursively parse a tag.
   *
   * A tag's header consists of:
   * - 2 bytes: tag name (where the lowest bit indicates presence of children; the actual tag id is the tag name shifted right by 1)
   * - 1 byte: tag type
   * - 4 bytes: tag payload length (contents length)
   *
   * If the tag has children (lowest bit set), the payload begins with a 2-byte children count,
   * followed by each child (recursively), and then the tag's own value (if any).
   */
  readTag(buffer, offset) {
    const start = offset;

    if (offset + 7 > buffer.length) {
      throw new Error("Insufficient data for tag header.");
    }
    const rawTagName = buffer.readUInt16BE(offset);
    offset += 2;
    const hasChildren = (rawTagName & 0x0001) !== 0;
    const tagId = rawTagName >> 1;
    const tagIdStr = this.getKeyByValue(EC_TAGS, tagId);
    const tagType = buffer.readUInt8(offset);
    const tagTypeStr = this.getKeyByValue(EC_TAG_TYPES, tagType);
    offset += 1;
    const tagLen = buffer.readUInt32BE(offset);
    offset += 4;

    let children = [];
    let tagValue;

    if (hasChildren) {
      // Read child count.
      if (offset + 2 > buffer.length) {
        throw new Error("Insufficient data for children count.");
      }
      const childCount = buffer.readUInt16BE(offset);
      offset += 2;
      // Recursively read each child.
      for (let i = 0; i < childCount; i++) {
        const result = this.readTag(buffer, offset);
        children.push(result.tag);
        offset = result.newOffset;
      }
      // The tag's own value is what remains of the payload.
      const headerSize = 7 + 2; // tag header + children count field
      const consumed = offset - (start + headerSize);
      const valueLength = tagLen - consumed;
      if (valueLength < 0) {
        throw new Error("Invalid tag length: negative value length");
      }
      tagValue = buffer.slice(offset, offset + valueLength);
      offset += valueLength;
    } else {
      tagValue = buffer.slice(offset, offset + tagLen);
      offset += tagLen;
    }

    let humanValue;
    if (tagType === EC_TAG_TYPES.EC_TAGTYPE_CUSTOM) {
      humanValue = undefined;
    } else if (tagType === EC_TAG_TYPES.EC_TAGTYPE_UINT8) {
      humanValue = tagValue.readUInt8(0);
    } else if (tagType === EC_TAG_TYPES.EC_TAGTYPE_UINT16) {
      humanValue = tagValue.readUInt16BE(0);
    } else if (tagType === EC_TAG_TYPES.EC_TAGTYPE_UINT32) {
      humanValue = tagValue.readUInt32BE(0);
    } else if (tagType === EC_TAG_TYPES.EC_TAGTYPE_UINT64) {
      humanValue = tagValue.readBigUInt64BE(0).toString();
    } else if (tagType === EC_TAG_TYPES.EC_TAGTYPE_UINT128) {
      humanValue = tagValue.readBigUInt64BE(0).toString() + tagValue.readBigUInt64BE(8).toString();
    } else if (tagType === EC_TAG_TYPES.EC_TAGTYPE_STRING) {
      humanValue = tagValue.toString('utf8').replace(/\0+$/, '');
    } else if (tagType === EC_TAG_TYPES.EC_TAGTYPE_DOUBLE) {
      humanValue = parseFloat(tagValue.toString('utf8').replace(/\0+$/, ''));
    } else if (tagType === EC_TAG_TYPES.EC_TAGTYPE_HASH16) {
      humanValue = tagValue.toString('hex');
      if (humanValue.length !== 32) console.warn('Warning: HASH16 incorrect length');
    } else if (tagType === EC_TAG_TYPES.EC_TAGTYPE_IPV4) {
      const ipBytes = tagValue.slice(0, 4);
      const portBytes = tagValue.slice(4, 6);
      const ipStr = Array.from(ipBytes).join('.');
      const port = portBytes.readUInt16BE(0);
      humanValue = `${ipStr}:${port}`;
    } else {
       throw new Error("Parsing unsopported tagType 0x" + tagType.toString(16)+ " for tagId " + tagIdStr);
    }

    const tag = {
      tagId,
      tagIdStr,
      tagType,
      tagTypeStr,
      tagLen,
      value: tagValue,
      humanValue: humanValue,
      children
    };

    return { tag, newOffset: offset };
  }

  /*
   * Authentication flow.
   */
  async authenticate() {
    if(DEBUG) console.log("[ECProtocol] Authenticating...");
    
    // Step 1: Build and send the AUTH_REQ packet.
    const clientNameTag = this.createTag(
      EC_TAGS.EC_TAG_CLIENT_NAME,
      EC_TAG_TYPES.EC_TAGTYPE_STRING,
      "amule-js"
    );
    const clientVerTag = this.createTag(
      EC_TAGS.EC_TAG_CLIENT_VERSION,
      EC_TAG_TYPES.EC_TAGTYPE_STRING,
      "0.1-beta"
    );
    const protocolVerTag = this.createTag(
      EC_TAGS.EC_TAG_PROTOCOL_VERSION,
      EC_TAG_TYPES.EC_TAGTYPE_UINT16,
      PROTOCOL_VERSION.EC_CURRENT_PROTOCOL_VERSION
    );

    const saltResponse = await this.sendPacket(EC_OPCODES.EC_OP_AUTH_REQ, [
      clientNameTag,
      clientVerTag,
      protocolVerTag,
    ]);

    // Step 2: Make sure we received the salt.
    if (saltResponse.opcode !== EC_OPCODES.EC_OP_AUTH_SALT) {
      throw new Error(
        "Authentication failed: Expected AUTH_SALT, received opcode: 0x" +
          saltResponse.opcode.toString(16)
      );
    }
    const saltBuffer = saltResponse.tags[0].value;
    const hexSalt = saltBuffer.toString("hex").toUpperCase();
    //console.log("Received salt:", hexSalt);

    // Step 3: Compute the password hash.
    const hashedSalt = crypto.createHash("md5").update(hexSalt).digest("hex");
    const hashedPass = crypto.createHash("md5")
      .update(this.password)
      .digest("hex");
    const passwdHash = crypto.createHash("md5")
      .update(hashedPass + hashedSalt)
      .digest("hex");
    //console.log("Computed password hash:", passwdHash);

    // Step 4: Send the AUTH_PASSWD packet.
    const passwdTag = this.createTag(
      EC_TAGS.EC_TAG_PASSWD_HASH,
      EC_TAG_TYPES.EC_TAGTYPE_HASH16,
      passwdHash
    );
    
    const authReply = await this.sendPacket(EC_OPCODES.EC_OP_AUTH_PASSWD, [passwdTag]);

    // Step 5: Check the server's response.
    if (authReply.opcode === EC_OPCODES.EC_OP_AUTH_OK) {
      if(DEBUG) console.log("Authentication successful");
    } else {
      throw new Error(
        "Authentication failed; received opcode: 0x" +
          authReply.opcode.toString(16)
      );
    }
  }

}

module.exports = ECProtocol;
