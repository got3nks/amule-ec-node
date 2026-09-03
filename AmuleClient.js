"use strict";

const ECProtocol = require("./ECProtocol");
const {
  EC_OPCODES,
  EC_TAGS,
  EC_TAG_TYPES,
  EC_SEARCH_TYPE,
  EC_VALUE_TYPE,
  EC_PREFS,
  EC_DETAIL_LEVEL
} = require("./ECDefs");

const DEBUG = false;

/**
 * Attempt to fix Mojibake filenames where UTF-8 bytes were decoded as Latin-1
 * (e.g. "Ã©" → "é"). Only applies the correction if the round-trip is clean
 * (no replacement characters), so already-correct strings are left untouched.
 * Strings containing characters above U+00FF (Cyrillic, Greek, CJK, etc.) are
 * already correctly decoded Unicode and are returned unchanged.
 */
function fixMojibake(str) {
  if (typeof str !== 'string') return str;
  for (let i = 0; i < str.length; i++) {
    if (str.charCodeAt(i) > 0xFF) return str;  // already real Unicode, leave it
  }
  try {
    const decoded = Buffer.from(str, 'latin1').toString('utf8');
    if (!decoded.includes('\uFFFD')) return decoded;
  } catch {}
  return str;
}

/**
 * Machine-readable `reason` codes returned by the category commands.
 *
 * Exposed as `AmuleClient.CATEGORY_REASON` so callers can branch on a constant
 * rather than on a string literal, and so the set is discoverable.
 * @readonly
 * @enum {string}
 */
const CATEGORY_REASON = Object.freeze({
  /** The download path was refused; everything else about the category was applied. */
  PATH_REJECTED: 'path_rejected',
  /** The category index does not exist; nothing was applied. */
  NO_SUCH_CATEGORY: 'no_such_category',
  /** Category 0 is the "all downloads" bucket and cannot be deleted. */
  DEFAULT_CATEGORY: 'default_category',
  /** aMule could not read the request as a category command at all. */
  MALFORMED_REQUEST: 'malformed_request',
  /** aMule refused the command in a shape this client does not recognise. */
  UNKNOWN: 'unknown'
});

/**
 * What the local core already knows about a search result, from
 * CSearchFile::DownloadStatus (src/SearchFile.h).
 *
 * Exposed as `AmuleClient.SEARCH_DOWNLOAD_STATUS` so callers can compare
 * against a constant instead of a magic number. The client reports only the
 * integer the core sends and never derives a label from it: this table mirrors
 * an enum that lives in another repo on another release cycle, so it belongs at
 * the call site, where a value it does not yet cover is visible rather than
 * silently unnamed.
 *
 * This is NOT the partfile status a download reports: aMule sends both under
 * EC_TAG_PARTFILE_STATUS and their low values overlap, so 2 is QUEUED on a
 * search result and PS_WAITING_FOR_HASH on a download. Search results carry it
 * as `downloadStatus`, downloads keep it as `status`, and nothing mixes them.
 * @readonly
 * @enum {number}
 */
const SEARCH_DOWNLOAD_STATUS = Object.freeze({
  /** Not known to this core. */
  NEW: 0,
  /** Successfully downloaded, or shared. */
  DOWNLOADED: 1,
  /** Downloading now. */
  QUEUED: 2,
  /** Cancelled. */
  CANCELED: 3,
  /** Cancelled once, downloading again. */
  QUEUEDCANCELED: 4
});

/**
 * The capability EC_OP_GET_SHARED_DIRS / EC_OP_SET_SHARED_DIRS are gated on.
 * A name rather than the tag id, because that is what the daemon's AUTH_OK
 * reply is recorded under.
 */
const EC_TAG_CAN_SHAREDDIRS_CONFIG_NAME = 'EC_TAG_CAN_SHAREDDIRS_CONFIG';

/**
 * Why aMule refused a shared directory, from the EC_TAG_SHAREDDIR_ERROR subtag.
 *
 * Exposed as `AmuleClient.SHAREDDIR_ERROR`. The daemon sends a number rather
 * than a sentence precisely so its locale never reaches the caller's UI, so
 * this client passes the number through and maps it to no wording of its own.
 * @readonly
 * @enum {number}
 */
const SHAREDDIR_ERROR = Object.freeze({
  /** The path does not exist, or is not a directory. */
  MISSING_OR_NOT_A_DIRECTORY: 1,
  /** The directory exists but the daemon cannot read it. */
  UNREADABLE: 2
});

class AmuleClient {
  /**
   * @param {string} host - aMule EC hostname or IP address
   * @param {number} port - aMule EC port (default 4712)
   * @param {string} password - EC access password
   * @param {Object} [options] - Additional options passed to ECProtocol
   * @param {number} [options.requestTimeout] - Per-request timeout in ms (default 30000)
   */
  constructor(host, port, password, options = {}) {
    this.session = new ECProtocol(host, port, password, options);

    // Clear incremental state on reconnection — aMule resets its
    // server-side diff state, so our XOR buffers and update cache
    // would produce corrupted data if not cleared.
    this.session.onReconnected = () => {
      this._ecBufferState = null;
      this._updateState = null;
      console.log('[AmuleClient] Cleared incremental state after reconnection');
    };
  }

  /**
   * Connect to aMule and authenticate.
   */
  async connect() {
    await this.session.connect();
    await this.session.authenticate();
  }

  /**
   * Feature tags the daemon advertised on its EC_OP_AUTH_OK reply, by name
   * (e.g. `'EC_TAG_CAN_SHAREDDIRS_CONFIG'`). Empty until connect() has run.
   * @returns {Set<string>}
   */
  get serverCapabilities() {
    return this.session.serverCapabilities;
  }

  /**
   * Whether the connected daemon advertised a given capability.
   * @param {string} tagName - e.g. `'EC_TAG_CAN_SHAREDDIRS_CONFIG'`
   * @returns {boolean}
   */
  hasCapability(tagName) {
    return this.session.hasCapability(tagName);
  }

  /**
   * Refuse to send an opcode the daemon never advertised.
   *
   * Not a nicety: an opcode a daemon does not know falls through to the tail of
   * ProcessRequest2, which logs and then hits wxFAIL — that aborts a debug
   * build outright, and compiles out in a release build, which answers
   * EC_OP_FAILED instead. Since the failure mode depends on how the daemon was
   * compiled, the only safe move is not to send it. Same hazard class as
   * amule-org/amule#1227.
   *
   * @param {string} tagName - Capability the command needs
   * @param {string} what - Human name of the command, for the error message
   * @throws {Error} If the capability was not advertised
   * @private
   */
  _requireCapability(tagName, what) {
    if (!this.hasCapability(tagName)) {
      throw new Error(
        `${what} needs a daemon advertising ${tagName}; this one did not. ` +
        `Nothing was sent — an unsupported opcode can abort a debug-built core.`
      );
    }
  }

  /**
   * Close the connection to aMule.
   */
  close() {
    this.session.close();
  }

  /**
   * Check if an EC response indicates success (EC_OP_NOOP).
   * @param {Object} response - Raw EC response
   * @returns {boolean} True if the response opcode is EC_OP_NOOP (0x01)
   * @private
   */
  _isSuccess(response) {
    return response.opcode === EC_OPCODES.EC_OP_NOOP;
  }

  /**
   * Interpret the reply to EC_OP_CREATE_CATEGORY / EC_OP_UPDATE_CATEGORY.
   *
   * These are the only commands whose EC_OP_FAILED is ambiguous, so the richer
   * parsing lives here rather than in _isSuccess() — a dozen other methods rely
   * on that meaning nothing more than "the opcode is EC_OP_NOOP".
   *
   * EC_OP_NOOP means everything was applied. On EC_OP_FAILED the discriminator
   * is which tags come back (src/ExternalConn.cpp), never the message text:
   * wxTRANSLATE only marks a string for extraction, so what arrives is the bare
   * English literal, and matching on it would bind this client to upstream
   * wording that no protocol rule holds still.
   *
   *   EC_TAG_CATEGORY + EC_TAG_CATEGORY_PATH
   *     The path could not be used — CPath::MakeDir failed — but the title,
   *     comment, colour and priority were stored and SaveCats() ran. The path
   *     tag carries the path aMule kept instead, which for an update is the
   *     category's previous path and for a create is the incoming directory.
   *     Consumers treat this as a success; see amule-org/amule#1213.
   *
   *   EC_TAG_CATEGORY + EC_TAG_STRING, no path tag
   *     No such category: the index is past the end of the category list and
   *     nothing at all was applied, not even a Notify_CategoryUpdate. The path
   *     tag is deliberately absent so this cannot be read as the case above.
   *     See amule-org/amule#1228.
   *
   * EC_OP_DELETE_CATEGORY has its own reply shapes and its own reader; see
   * _parseCategoryDeleteResult().
   *
   * Cores built before amule-org/amule#1228 never send the second shape — they
   * abort on the out-of-range index instead of replying — so it is parsed when
   * present and never required. Such a core answers an out-of-range update with
   * the first shape instead, and this client will report it as a partially
   * applied update, because on the wire that is all it is told.
   *
   * @param {Object} response - Raw EC response
   * @returns {{success: boolean, applied: 'full'|'partial'|'none', reason: string|null, message: string|null, keptPath: string|null, categoryId: number|null}}
   * @private
   */
  _parseCategoryResult(response) {
    const categoryId = this.parseCategoryIdFromResponse(response);
    const pathTag = response.tags?.find(t => t.tagId === EC_TAGS.EC_TAG_CATEGORY_PATH);
    const stringTag = response.tags?.find(t => t.tagId === EC_TAGS.EC_TAG_STRING);
    const message = typeof stringTag?.humanValue === 'string' ? stringTag.humanValue : null;

    if (this._isSuccess(response)) {
      return { success: true, applied: 'full', reason: null, message, keptPath: null, categoryId };
    }

    // Below, `message` is only ever tested for presence. Its text is carried to
    // the caller and never read here — see the note on wxTRANSLATE above.

    if (pathTag) {
      return {
        success: true,
        applied: 'partial',
        reason: CATEGORY_REASON.PATH_REJECTED,
        message,
        keptPath: typeof pathTag.humanValue === 'string' ? pathTag.humanValue : null,
        categoryId
      };
    }

    if (stringTag) {
      return {
        success: false,
        applied: 'none',
        reason: CATEGORY_REASON.NO_SUCH_CATEGORY,
        message,
        keptPath: null,
        categoryId
      };
    }

    return {
      success: false,
      applied: 'none',
      reason: CATEGORY_REASON.UNKNOWN,
      message: null,
      keptPath: null,
      categoryId
    };
  }

  /**
   * Interpret the reply to EC_OP_DELETE_CATEGORY.
   *
   * Separate from _parseCategoryResult() because the two opcodes disagree on
   * what a bare EC_TAG_STRING means. There it is the single "no such category"
   * refusal; here it covers three, so reusing that reader would label a
   * protected or malformed delete as a missing category.
   *
   * amule-org/amule#1232 gives delete the shape #1228 established, and the
   * discriminator stays structural — the echoed index, not the wording:
   *
   *   no EC_TAG_CATEGORY          The request did not carry a readable index.
   *                               ("Malformed category request.")
   *   EC_TAG_CATEGORY == 0        The "all downloads" bucket, which
   *                               MuleNotify::CategoryDelete refuses outright.
   *   EC_TAG_CATEGORY > 0         Past the end of the list; CPreferences::
   *                               RemoveCat is bounds-checked and no-ops.
   *
   * EC_TAG_CATEGORY_PATH is never sent for a delete and is not looked for: on a
   * failed category command that tag means "everything but the path was
   * applied" (amule-org/amule#1213), which is meaningless here.
   *
   * BACKWARD COMPATIBILITY: a core predating #1232 answers EC_OP_NOOP to every
   * delete, including the three it discards, so against one of those this
   * reports success for a delete that did nothing. That is not a regression —
   * it is what the old bare boolean said too — and it cannot be detected from
   * the reply, which carries no version. A caller that must be certain has to
   * re-read getCategories(). Nothing here requires a failure reply to arrive,
   * so the parsing is purely additive against any core.
   *
   * @param {Object} response - Raw EC response
   * @returns {{success: boolean, applied: 'full'|'none', reason: string|null, message: string|null}}
   * @private
   */
  _parseCategoryDeleteResult(response) {
    const stringTag = response.tags?.find(t => t.tagId === EC_TAGS.EC_TAG_STRING);
    const message = typeof stringTag?.humanValue === 'string' ? stringTag.humanValue : null;

    if (this._isSuccess(response)) {
      return { success: true, applied: 'full', reason: null, message: null };
    }

    // Every branch below reads the opcode, which tags are present, and the
    // echoed index. None reads the message text.
    const categoryId = this.parseCategoryIdFromResponse(response);
    let reason = CATEGORY_REASON.UNKNOWN;
    if (categoryId === null) {
      // Only the malformed-request branch omits the index entirely.
      if (stringTag) reason = CATEGORY_REASON.MALFORMED_REQUEST;
    } else if (categoryId === 0) {
      reason = CATEGORY_REASON.DEFAULT_CATEGORY;
    } else {
      reason = CATEGORY_REASON.NO_SUCH_CATEGORY;
    }

    return { success: false, applied: 'none', reason, message };
  }

  /**
   * Send a command targeting a server by IP and port.
   * @param {number} opcode - EC opcode to send
   * @param {string} ip - Server IP address
   * @param {number} port - Server port
   * @returns {Promise<boolean>} True if the command succeeded
   * @private
   */
  async _sendServerCommand(opcode, ip, port) {
    const reqTags = [
      this.session.createTag(EC_TAGS.EC_TAG_SERVER, EC_TAG_TYPES.EC_TAGTYPE_IPV4, {ip, port})
    ];
    const response = await this.session.sendPacket(opcode, reqTags);
    if (DEBUG) console.log("[DEBUG] Received response:", response);
    return this._isSuccess(response);
  }

  /**
   * Send a command targeting a file by hash.
   * @param {number} opcode - EC opcode to send
   * @param {string} fileHash - MD4 hash of the file
   * @returns {Promise<boolean>} True if the command succeeded
   * @private
   */
  async _sendFileCommand(opcode, fileHash) {
    const reqTags = [
      this.session.createTag(EC_TAGS.EC_TAG_PARTFILE, EC_TAG_TYPES.EC_TAGTYPE_HASH16, fileHash)
    ];
    const response = await this.session.sendPacket(opcode, reqTags);
    if (DEBUG) console.log("[DEBUG] Received response:", response);
    return this._isSuccess(response);
  }

  /**
   * Send a simple request and return the response as a tag tree.
   * @param {number} opcode - EC opcode to send
   * @returns {Promise<Object>} Parsed tag tree
   * @private
   */
  async _requestTagTree(opcode) {
    const response = await this.session.sendPacket(opcode, []);
    if (DEBUG) console.log("[DEBUG] Received response:", response);
    return this.buildTagTree(response.tags);
  }

  /**
   * Get the current connection state (ed2k server, Kad network).
   * @returns {Promise<Object>} Tag tree with connection state fields
   */
  async getConnectionState() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_CONNSTATE);
  }

  /**
   * Get aMule statistics (upload/download speed, shared file count, etc.).
   * @returns {Promise<Object>} Tag tree with stats fields
   */
  async getStats() {
    return this._requestTagTree(EC_OPCODES.EC_OP_STAT_REQ);
  }

  /**
   * Get the full statistics tree (hierarchical stats with node IDs).
   * @returns {Promise<Object>} Tag tree with nested stats
   */
  async getStatsTree() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_STATSTREE);
  }

  /**
   * Get ed2k server info (message of the day, etc.).
   * @returns {Promise<Object>} Tag tree with server info
   */
  async getServerInfo() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_SERVERINFO);
  }

  /**
   * Get aMule log messages.
   * @returns {Promise<Object>} Tag tree with log entries
   */
  async getLog() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_LOG);
  }

  /**
   * Get aMule debug log messages.
   * @returns {Promise<Object>} Tag tree with debug log entries
   */
  async getDebugLog() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_DEBUGLOG);
  }

  /**
   * Get the list of ed2k servers.
   * @returns {Promise<Object>} Tag tree with server entries
   */
  async getServerList() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_SERVER_LIST);
  }

  /**
   * Remove an ed2k server from the server list.
   * @param {string} ip - Server IP address
   * @param {number} port - Server port
   * @returns {Promise<boolean>} True if the server was removed successfully
   */
  async removeServer(ip, port) {
    return this._sendServerCommand(EC_OPCODES.EC_OP_SERVER_REMOVE, ip, port);
  }

  /**
   * Connect to an ed2k server.
   * @param {string} ip - Server IP address
   * @param {number} port - Server port
   * @returns {Promise<boolean>} True if connection was initiated successfully
   */
  async connectServer(ip, port) {
    return this._sendServerCommand(EC_OPCODES.EC_OP_SERVER_CONNECT, ip, port);
  }

  /**
   * Disconnect from an ed2k server.
   * @param {string} ip - Server IP address
   * @param {number} port - Server port
   * @returns {Promise<boolean>} True if disconnection was successful
   */
  async disconnectServer(ip, port) {
    return this._sendServerCommand(EC_OPCODES.EC_OP_SERVER_DISCONNECT, ip, port);
  }

  /**
   * Get the upload queue (clients waiting to download from us).
   * @returns {Promise<Object>} Tag tree with upload queue entries
   */
  async getUploadingQueue() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_ULOAD_QUEUE);
  }

  /**
   * Get the full list of shared files (non-incremental).
   * Unlike getUpdate(), this always returns the complete list.
   * @returns {Promise<{fileName: string, fileHash: string, fileSize: number, transferred: number, transferredTotal: number, reqCount: number, reqCountTotal: number, acceptedCount: number, acceptedCountTotal: number, priority: number, path: string, completeSources: number, onQueue: number, ed2kLink: string, raw: Object}[]>} Parsed shared file objects
   */
  async getSharedFiles() {
    if (DEBUG) console.log("[DEBUG] Requesting shared files...");

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_SHARED_FILES, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return response.tags.map(tag => ({
      ...this._parseSharedFileFields(tag),
      raw: this.buildTagTree(tag.children)
    }));
  }

  /**
   * Clear completed downloads from aMule's download list.
   * Sends EC_OP_CLEAR_COMPLETED with EC_TAG_ECID children for each ecid to clear.
   *
   * @param {number[]} [ecids] - Specific ecids to clear. If omitted, clears all
   *   downloads at 100% from the internal _updateState cache.
   * @returns {Promise<{ opcode: number, cleared: number[] }>} Response opcode and list of ecids sent.
   */
  async clearCompleted(ecids) {
    if (DEBUG) console.log("[DEBUG] Clearing completed downloads...");

    // If no ecids specified, find all completed downloads from cache
    if (!ecids) {
      ecids = [];
      if (this._updateState) {
        for (const [ecid, dl] of this._updateState.downloads) {
          if (parseFloat(dl.progress) >= 100) {
            ecids.push(ecid);
          }
        }
      }
    }

    if (ecids.length === 0) {
      if (DEBUG) console.log("[DEBUG] No completed downloads to clear");
      return { opcode: 0, cleared: [] };
    }

    const tags = ecids.map(ecid =>
      this.session.createTag(EC_TAGS.EC_TAG_ECID, EC_TAG_TYPES.EC_TAGTYPE_UINT32, ecid)
    );

    if (DEBUG) console.log(`[DEBUG] Sending EC_OP_CLEAR_COMPLETED with ${tags.length} ecid(s):`, ecids);

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_CLEAR_COMPLETED, tags);

    if (DEBUG) console.log("[DEBUG] Clear completed response opcode:", response.opcode);

    return { opcode: response.opcode, cleared: ecids };
  }

  /**
   * Tell aMule to reload its shared files from disk.
   * @returns {Promise<boolean>} True if the reload was initiated successfully
   */
  async refreshSharedFiles() {
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SHAREDFILES_RELOAD, []);
    if (DEBUG) console.log("[DEBUG] Received response:", response);
    return this._isSuccess(response);
  }

  /**
   * Get the full download queue (non-incremental).
   * Unlike getUpdate(), this always returns the complete list.
   * @returns {Promise<Object[]>} Array of download objects with parsed fields
   */
  async getDownloadQueue() {
    if (DEBUG) console.log("[DEBUG] Requesting downloaded files...");

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_DLOAD_QUEUE, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return response.tags.map(tag => {
      const fields = this._parseDownloadFields(tag);
      // Decode buffer fields (full data, no XOR — use ecid=0 as throwaway state)
      this._reconstructBufferFields(0, fields);
      if (this._ecBufferState) this._ecBufferState.delete(0);
      fields.raw = this.buildTagTree(tag.children);
      return fields;
    });
  }

  /**
   * Request an incremental update from aMule containing files, clients, and servers.
   *
   * IMPORTANT: EC_OP_GET_UPDATE with EC_DETAIL_INC_UPDATE is **stateful and incremental**.
   * The first call returns full state for all objects. Subsequent calls return only
   * fields that changed since the last call. This method maintains an internal cache
   * (_updateState) and merges incremental updates automatically.
   *
   * Returns { downloads, sharedFiles, clients } where:
   * - downloads: array of download objects (EC_TAG_PARTFILE) with all fields
   * - sharedFiles: array of shared file objects (EC_TAG_KNOWNFILE) with all fields
   * - clients: array of client/peer objects (EC_TAG_CLIENT) with all fields
   */
  async getUpdate() {
    if (DEBUG) console.log("[DEBUG] Requesting incremental update");

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_DETAIL_LEVEL,
        EC_TAG_TYPES.EC_TAGTYPE_UINT8,
        EC_DETAIL_LEVEL.EC_DETAIL_INC_UPDATE
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_UPDATE, reqTags);

    if (DEBUG) console.log("[DEBUG] Received update response, tags:", response.tags?.length);

    // Initialize state cache on first call
    if (!this._updateState) {
      this._updateState = {
        downloads: new Map(),    // ecid → download object
        sharedFiles: new Map(),  // ecid → shared file object
        clients: new Map(),      // ecid → client object
      };
    }

    // Parse and merge downloads (EC_TAG_PARTFILE tags at root level)
    // Collect ecids seen in this response for set-based reconciliation
    const seenDownloads = new Set();
    for (const tag of response.tags) {
      if (tag.tagId !== EC_TAGS.EC_TAG_PARTFILE) continue;
      const ecid = tag.humanValue || tag.value;
      seenDownloads.add(ecid);
      const existing = this._updateState.downloads.get(ecid) || { ecid };
      const updates = this._parseDownloadFields(tag);
      // RLE-decode + XOR-reconstruct buffer fields (partStatus, gapStatus, reqStatus)
      this._reconstructBufferFields(ecid, updates);
      // Merge raw tag tree incrementally (preserves fields from prior full update)
      updates.raw = this.deepMergeRaw(existing.raw || {}, this.buildTagTree(tag.children));
      const merged = { ...existing, ...updates };
      // Recalculate progress after merge (incremental may update only one of the two size fields)
      if (merged.fileSize > 0 && merged.fileSizeDownloaded !== undefined) {
        merged.progress = ((merged.fileSizeDownloaded / merged.fileSize) * 100).toFixed(2);
      }
      this._updateState.downloads.set(ecid, merged);
    }
    // Remove downloads no longer present in the response (completed/cancelled)
    for (const ecid of this._removedEcids(response, seenDownloads, this._updateState.downloads.keys())) {
      if (this._updateState.downloads.has(ecid)) {
        if (DEBUG) console.log(`[DEBUG] Removing stale download ecid=${ecid}`);
        this._updateState.downloads.delete(ecid);
        if (this._ecBufferState) this._ecBufferState.delete(ecid);
      }
    }

    // Track completed downloads for clearCompleted.
    // aMule keeps completed downloads in the PARTFILE list until cleared via
    // EC_OP_CLEAR_COMPLETED. Clearing triggers RenewECID(), which causes the
    // next getUpdate() to return the file as a new KNOWNFILE (shared file).
    // We wait for status 9 (PS_COMPLETE) before clearing, since status 8
    // (PS_COMPLETING) means aMule is still hashing/moving the file.
    if (!this._completedHashes) this._completedHashes = new Set();
    if (!this._pendingClear) this._pendingClear = new Map(); // hash → ecid

    for (const dl of this._updateState.downloads.values()) {
      if (parseFloat(dl.progress) >= 100 && dl.fileHash) {
        if (!this._completedHashes.has(dl.fileHash)) {
          this._completedHashes.add(dl.fileHash);
          if (DEBUG) console.log(`[DEBUG] Download completed: hash=${dl.fileHash}, name=${dl.fileName}, status=${dl.status}`);
        }
        // Queue for clearing (will be sent when status reaches PS_COMPLETE)
        if (!this._pendingClear.has(dl.fileHash)) {
          this._pendingClear.set(dl.fileHash, dl.ecid);
        }
      }
    }

    // Parse and merge shared files (EC_TAG_KNOWNFILE tags at root level)
    const seenSharedFiles = new Set();
    for (const tag of response.tags) {
      if (tag.tagId !== EC_TAGS.EC_TAG_KNOWNFILE) continue;
      const ecid = tag.humanValue || tag.value;
      seenSharedFiles.add(ecid);
      const existing = this._updateState.sharedFiles.get(ecid) || { ecid };
      const updates = this._parseSharedFileFields(tag);
      updates.raw = this.deepMergeRaw(existing.raw || {}, this.buildTagTree(tag.children));
      this._updateState.sharedFiles.set(ecid, { ...existing, ...updates });
    }
    // Remove shared files no longer present (unshared). Which reply shape says
    // "gone" depends on the negotiated protocol — see _removedEcids().
    for (const ecid of this._removedEcids(response, seenSharedFiles, this._updateState.sharedFiles.keys())) {
      if (this._updateState.sharedFiles.has(ecid)) {
        if (DEBUG) console.log(`[DEBUG] Removing stale shared file ecid=${ecid}`);
        this._updateState.sharedFiles.delete(ecid);
      }
    }

    // Clear completed downloads that have reached PS_COMPLETE (status 9).
    // This removes them from the download list and triggers RenewECID(),
    // causing the next getUpdate() to return them as new KNOWNFILEs.
    if (this._pendingClear.size > 0) {
      const ecidsToClear = [];
      const hashesToRemove = [];

      for (const [hash, ecid] of this._pendingClear) {
        const dl = [...this._updateState.downloads.values()].find(d => d.fileHash === hash);
        if (!dl) {
          // Download already gone (cleared externally or by aMule)
          hashesToRemove.push(hash);
        } else if (dl.status === 9) {
          // PS_COMPLETE — ready to clear
          ecidsToClear.push(ecid);
          hashesToRemove.push(hash);
          if (DEBUG) console.log(`[DEBUG] Clearing completed download: hash=${hash}, ecid=${ecid}`);
        }
        // status 8 (PS_COMPLETING) — keep waiting
      }

      for (const hash of hashesToRemove) {
        this._pendingClear.delete(hash);
      }

      if (ecidsToClear.length > 0) {
        try {
          await this.clearCompleted(ecidsToClear);
        } catch (err) {
          if (DEBUG) console.log(`[DEBUG] Failed to clear completed:`, err.message);
        }
      }
    }

    // Parse and merge clients from EC_TAG_CLIENT container
    const clientContainer = response.tags.find(tag => tag.tagId === EC_TAGS.EC_TAG_CLIENT);
    if (clientContainer && clientContainer.children) {
      const seenClients = new Set();
      const clientTags = clientContainer.children.filter(c => c.tagId === EC_TAGS.EC_TAG_CLIENT);
      for (const clientTag of clientTags) {
        const ecid = clientTag.humanValue || clientTag.value;
        seenClients.add(ecid);
        const existing = this._updateState.clients.get(ecid) || { ecid };
        const updates = this._parseClientFields(clientTag);
        this._updateState.clients.set(ecid, { ...existing, ...updates });
      }
      // Remove disconnected clients no longer present
      // Not _removedEcids(): the daemon emits the whole client list on every
      // reply regardless of the negotiated protocol — no skip-unchanged, no
      // tombstones — so absence really does mean gone here.
      for (const ecid of [...this._updateState.clients.keys()]) {
        if (!seenClients.has(ecid)) {
          if (DEBUG) console.log(`[DEBUG] Removing stale client ecid=${ecid}`);
          this._updateState.clients.delete(ecid);
        }
      }
    }

    return {
      downloads: Array.from(this._updateState.downloads.values()),
      sharedFiles: Array.from(this._updateState.sharedFiles.values()),
      clients: Array.from(this._updateState.clients.values()),
    };
  }

  /**
   * Resolve a network to an EC_SEARCH_TYPE value.
   * @param {string|number} network - 'global', 'local', 'kad', or an EC_SEARCH_TYPE value
   * @returns {number}
   * @throws {Error} If it is neither
   * @private
   */
  _normaliseNetwork(network) {
    if (Object.values(EC_SEARCH_TYPE).includes(network)) return network;
    switch (network) {
      case 'global': return EC_SEARCH_TYPE.EC_SEARCH_GLOBAL;
      case 'local':  return EC_SEARCH_TYPE.EC_SEARCH_LOCAL;
      case 'kad':    return EC_SEARCH_TYPE.EC_SEARCH_KAD;
    }
    throw new Error(`Invalid network type: ${network}`);
  }

  /**
   * Start a search and return as soon as the daemon has accepted it.
   *
   * Pair with {@link AmuleClient#getSearchProgress} and
   * {@link AmuleClient#getSearchResults} to poll from the caller, leaving the EC
   * connection free between polls. {@link AmuleClient#searchAndWaitResults} does
   * the same in one call but holds the connection throughout.
   *
   * CALLERS MUST SERIALISE SEARCHES. Without EC_TAG_CAN_MULTI_SEARCH, which this
   * client does not negotiate, every EC_OP_SEARCH_START clears the previous
   * result set: a search started before the last one is read back loses those
   * results. ed2k searches share one slot daemon-side and Kad is tracked per id,
   * but on this single-bucket path that distinction buys nothing. Lock around
   * start→results in the caller; this client deliberately does not.
   *
   * @param {string} query - Search query string
   * @param {string|number} network - 'global', 'local', 'kad', or an EC_SEARCH_TYPE value
   * @param {string|null} [extension] - Optional file extension filter
   * @returns {Promise<{ started: boolean, message: string|null, tags: Object[] }>}
   *   `started` is false when the daemon refused, `message` its text. Reported
   *   rather than thrown, so searchAndWaitResults() keeps polling on as it
   *   always has; a caller driving the loop should check it.
   * @throws {Error} If `network` is not a recognised network
   */
  async startSearch(query, network, extension = null) {
    if (DEBUG) console.log("[DEBUG] Requesting search...");

    const searchType = this._normaliseNetwork(network);
    // Before the round trip: a local search is judged complete by elapsed time.
    this._searchContext = { network: searchType, startedAt: Date.now() };

    // Prepare request
    let children = [
      {
        tagId: EC_TAGS.EC_TAG_SEARCH_NAME,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_STRING,
        value: query
      }
    ];
    if (typeof extension === 'string' && extension.length > 0) {
      children.push({
        tagId: EC_TAGS.EC_TAG_SEARCH_EXTENSION,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_STRING,
        value: extension
      });
    }
    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_SEARCH_TYPE,
        EC_TAG_TYPES.EC_TAGTYPE_UINT8,
        searchType,
        children
      )
    ];
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SEARCH_START, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    const messageTag = response.tags?.find(t => t.tagId === EC_TAGS.EC_TAG_STRING);
    return {
      started: response.opcode !== EC_OPCODES.EC_OP_FAILED,
      message: typeof messageTag?.humanValue === 'string' ? messageTag.humanValue : null,
      tags: response.tags
    };
  }

  /**
   * Start a search on the specified network.
   * @param {string} query - Search query string
   * @param {number} network - Network type (EC_SEARCH_TYPE value)
   * @param {string|null} [extension] - Optional file extension filter
   * @returns {Promise<Object[]>} Raw response tags
   * @deprecated Use {@link AmuleClient#startSearch}
   * @private
   */
  async _search(query, network, extension = null) {
    return (await this.startSearch(query, network, extension)).tags;
  }

  /**
   * Whether a search on `network` is finished. aMule reports no progress for a
   * local search, so that one goes by elapsed time, as this has always done.
   *
   * @param {number|null} network - EC_SEARCH_TYPE value of the running search
   * @param {number|null} progress - EC_TAG_SEARCH_STATUS value, if sent
   * @param {number|null} elapsedMs - Since startSearch(), if known
   * @returns {boolean}
   * @private
   */
  _isSearchComplete(network, progress, elapsedMs) {
    switch (network) {
      case EC_SEARCH_TYPE.EC_SEARCH_KAD:
        return progress === 0xFFFF || progress === 0xFFFE;
      case EC_SEARCH_TYPE.EC_SEARCH_GLOBAL:
        return progress === 100 || progress === 0;
      case EC_SEARCH_TYPE.EC_SEARCH_LOCAL:
        return elapsedMs !== null && elapsedMs >= 10000;
      default:
        return false;
    }
  }

  /**
   * Poll the progress of the running search. One short round trip, so a caller
   * can drive its own loop and leave the connection free in between.
   *
   * @returns {Promise<{ complete: boolean, progress: number|null, network: number|null, elapsedMs: number|null, tags: Object[] }>}
   *   `complete` applies the per-network rule so callers need not re-derive it.
   *   It is false when no search was started through this client — the network
   *   is then unknown and there is nothing to judge against.
   */
  async getSearchProgress() {
    if (DEBUG) console.log("[DEBUG] Requesting search request status...");

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SEARCH_PROGRESS, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    const statusTag = response.tags?.find(t => t.tagId === EC_TAGS.EC_TAG_SEARCH_STATUS);
    const progress = statusTag?.humanValue ?? null;
    const context = this._searchContext;
    const network = context ? context.network : null;
    const elapsedMs = context ? Date.now() - context.startedAt : null;

    return {
      complete: this._isSearchComplete(network, progress, elapsedMs),
      progress,
      network,
      elapsedMs,
      tags: response.tags
    };
  }

  /**
   * Get the progress status of an ongoing search.
   * @returns {Promise<Object[]>} Raw response tags with search progress
   * @deprecated Use {@link AmuleClient#getSearchProgress}
   * @private
   */
  async _getSearchRequestStatus() {
    return (await this.getSearchProgress()).tags;
  }

  /**
   * Get the results of a completed search.
   *
   * aMule can return several filenames for one hash — the expandable tree the
   * GUI shows — but only if the caller asks. Grouping is opt-in: the daemon
   * checks for the mere presence of an EC_TAG_SEARCH_PARENT tag on the request
   * and otherwise stays parents-only, which is why this defaults to off and
   * existing callers see exactly what they saw before.
   *
   * With `groupByHash`, children come back as further TOP-LEVEL tags rather
   * than nested ones, each carrying its parent's ECID. They are rebuilt into a
   * `children` array here, because the source-count sort would otherwise
   * scatter them away from their parent — children carry their own counts.
   *
   * Sending the flag to a daemon predating the feature (aMule 2f31fd6fe, in no
   * release as of 3.0.1) is harmless: the unknown tag is ignored and the reply
   * is parents-only. An empty `children` array is therefore the normal result
   * on such a core and is not an error.
   *
   * Which name aMule elects as the parent is not necessarily the most
   * informative one, so treat the parent as one name among the group rather
   * than the best one.
   *
   * @param {Object} [options]
   * @param {boolean} [options.groupByHash=false] - Ask for the same-hash siblings
   * @returns {Promise<{ resultsLength: number, totalLength: number, results: Object[] }>}
   *   `results` is sorted by source count, as before. `resultsLength` counts it;
   *   `totalLength` counts every result including nested children, so the two
   *   differ only when grouping is on. Each result gains `id` (its ECID). With
   *   grouping, parents gain `children` (possibly empty, sorted the same way)
   *   and children keep the `parentId` they arrived with. A child whose parent
   *   is missing from the reply is kept at the top level rather than dropped,
   *   with its `parentId` left in place to say so.
   *
   *   Every result also gains `downloadStatus`, on children as well as parents:
   *   the integer the core sent under EC_TAG_PARTFILE_STATUS, reported as-is and
   *   omitted entirely when it sent no tag. Compare it against
   *   `AmuleClient.SEARCH_DOWNLOAD_STATUS` rather than a bare number. Note that
   *   a result reads NEW unless the LOCAL core already knows the file, so an
   *   all-NEW result set says nothing about the wider network.
   */
  async getSearchResults(options = {}) {
    const { groupByHash = false } = options;
    if (DEBUG) console.log("[DEBUG] Requesting search results, groupByHash:", groupByHash);

    // aMule tests only that the tag is present, never its value.
    const reqTags = groupByHash
      ? [this.session.createTag(EC_TAGS.EC_TAG_SEARCH_PARENT, EC_TAG_TYPES.EC_TAGTYPE_UINT32, 0)]
      : [];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SEARCH_RESULTS, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    const bySourceCount = (a, b) => (b.sourceCount || 0) - (a.sourceCount || 0);

    const flat = (response.tags || [])
      .filter(tag => tag.tagId === EC_TAGS.EC_TAG_SEARCHFILE)
      .map(tag => {
        const fields = this._parseDownloadFields(tag);
        fields.id = this._tagOwnId(tag);
        // On a search result EC_TAG_PARTFILE_STATUS is CSearchFile::
        // DownloadStatus, not the partfile status _parseDownloadFields() reads
        // it as for a download. Republish it under its own name so the two
        // enums cannot be confused; `status` is left alone for compatibility.
        // Verbatim: the integer the core sent, absent when it sent no tag.
        if (fields.status !== undefined) {
          fields.downloadStatus = fields.status;
        }
        return fields;
      });

    if (!groupByHash) {
      flat.sort(bySourceCount);
      return { resultsLength: flat.length, totalLength: flat.length, results: flat };
    }

    const byId = new Map();
    for (const r of flat) {
      if (r.id !== null) byId.set(r.id, r);
    }

    const parents = [];
    for (const r of flat) {
      const parent = r.parentId !== undefined ? byId.get(r.parentId) : undefined;
      if (parent && parent !== r) {
        (parent.children || (parent.children = [])).push(r);
      } else {
        // A parent, or a child whose parent did not come back. Keeping the
        // orphan visible beats dropping a filename the caller asked for.
        parents.push(r);
      }
    }

    for (const p of parents) {
      if (!p.children) p.children = [];
      p.children.sort(bySourceCount);
    }
    parents.sort(bySourceCount);

    return { resultsLength: parents.length, totalLength: flat.length, results: parents };
  }

  /**
   * Start a search and poll until results are ready (up to 120s timeout).
   *
   * Holds the EC connection for the whole wait, so a consumer serialising EC
   * calls blocks everything else meanwhile. Drive {@link AmuleClient#startSearch},
   * {@link AmuleClient#getSearchProgress} and {@link AmuleClient#getSearchResults}
   * yourself to avoid that; startSearch()'s serialisation warning applies either way.
   *
   * @param {string} query - Search query string
   * @param {string|number} network - Network type: 'global', 'local', 'kad', or EC_SEARCH_TYPE value
   * @param {string} [extension] - Optional file extension filter
   * @param {Object} [options] - Passed through to {@link AmuleClient#getSearchResults}
   * @param {boolean} [options.groupByHash=false] - Ask for the same-hash siblings
   * @returns {Promise<{ resultsLength: number, totalLength: number, results: Object[] }>} Search results sorted by source count
   */
  async searchAndWaitResults(query, network, extension, options = {}) {
    const timeoutMs = 120000;
    const intervalMs = 1000;
    const startTime = Date.now();

    await this.startSearch(query, network, extension);

    if (DEBUG) console.log("[DEBUG] Waiting for search to complete...");
    await new Promise(resolve => setTimeout(resolve, 5000)); // for global/local searches, let's give amule some time for the progress to re-initialize

    while (true) {
      if (Date.now() - startTime >= timeoutMs) throw new Error("Search timed out");

      const status = await this.getSearchProgress();
      if (status.complete) {
        if (DEBUG) console.log("[DEBUG] Search completed.");
        break;
      }

      if (DEBUG) console.log(`[DEBUG] Search ${status.network} progress: ${status.progress}`);
      await new Promise(resolve => setTimeout(resolve, intervalMs));
    }

    return this.getSearchResults?.(options) ?? null;
  }


  /**
   * Ask aMule to fetch the list of files shared by a specific user on the ed2k
   * network (aMule's "View shared files" feature).
   *
   * This sends EC_OP_FRIEND with an EC_TAG_FRIEND_SHARED container holding
   * either an EC_TAG_CLIENT (peer ECID) or EC_TAG_FRIEND (friend ECID) subtag,
   * which makes aMule request the remote client's shared file list over ed2k
   * (see Get_EC_Response_Friend in ExternalConn.cpp → RequestSharedFileList).
   *
   * IMPORTANT: this is asynchronous. The EC command only *triggers* the request
   * and aMule returns EC_OP_NOOP immediately. When the peer eventually answers,
   * aMule injects the received files into its search-result list
   * (CSearchList::ProcessSharedFileList), so they are read back via
   * getSearchResults(). Use getClientSharedFiles() to do both steps at once.
   *
   * The user must already be known to aMule as a CUpDownClient (e.g. a download
   * source, an upload/queue peer, or a friend). Obtain the ECID from getUpdate()
   * (the `clients` array) or from the friend list.
   *
   * @param {number} ecid - ECID of the client (or friend) to query
   * @param {Object} [options]
   * @param {boolean} [options.asFriend=false] - Treat `ecid` as a friend ECID
   *   (EC_TAG_FRIEND) rather than a peer client ECID (EC_TAG_CLIENT)
   * @returns {Promise<boolean>} True if aMule accepted the request (EC_OP_NOOP)
   */
  async requestClientSharedFiles(ecid, options = {}) {
    const { asFriend = false } = options;
    if (!Number.isInteger(ecid) || ecid < 0) {
      throw new TypeError('requestClientSharedFiles: ecid must be a non-negative integer');
    }

    if (DEBUG) console.log(`[DEBUG] Requesting shared file list for ${asFriend ? 'friend' : 'client'} ecid=${ecid}`);

    const subTagId = asFriend ? EC_TAGS.EC_TAG_FRIEND : EC_TAGS.EC_TAG_CLIENT;
    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_FRIEND_SHARED,
        EC_TAG_TYPES.EC_TAGTYPE_CUSTOM,
        undefined,  // container tag — carries only the subtag below
        [
          {
            tagId: subTagId,
            tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT32,
            value: ecid
          }
        ]
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_FRIEND, reqTags);

    if (DEBUG) console.log("[DEBUG] requestClientSharedFiles response:", response);

    if (response.opcode === EC_OPCODES.EC_OP_FAILED) {
      const errorMsg = response.tags?.find(t => t.tagId === EC_TAGS.EC_TAG_STRING)?.humanValue;
      throw new Error(errorMsg || 'Failed to request shared file list');
    }

    return this._isSuccess(response);
  }

  /**
   * Request a user's shared files and wait for the ed2k answer to arrive.
   *
   * Convenience wrapper that triggers requestClientSharedFiles() and then polls
   * the search-result list (where aMule delivers the peer's answer) until new
   * results show up or the timeout elapses.
   *
   * NOTE: aMule stores these alongside regular search results and does not tag
   * them by peer, so results from a prior search may also be present. Poll from
   * a clean state (e.g. right after EC_OP_SEARCH_START clears the list) for the
   * cleanest output.
   *
   * @param {number} ecid - ECID of the client (or friend) to query
   * @param {Object} [options]
   * @param {boolean} [options.asFriend=false] - Treat `ecid` as a friend ECID
   * @param {number} [options.timeoutMs=30000] - Max time to wait for the answer
   * @param {number} [options.intervalMs=1000] - Poll interval in ms
   * @returns {Promise<{ resultsLength: number, results: Object[] }>} Shared files
   *   (parsed like search results), sorted by source count
   */
  async getClientSharedFiles(ecid, options = {}) {
    const { asFriend = false, timeoutMs = 30_000, intervalMs = 1000 } = options;

    const before = (await this.getSearchResults()).resultsLength;

    await this.requestClientSharedFiles(ecid, { asFriend });

    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      await new Promise(resolve => setTimeout(resolve, intervalMs));
      const current = await this.getSearchResults();
      if (current.resultsLength > before) {
        return current;
      }
    }

    if (DEBUG) console.log("[DEBUG] getClientSharedFiles: timed out waiting for peer answer");
    return this.getSearchResults();
  }

  /**
   * Download a file from search results.
   * @param {string} fileHash - MD4 hash of the file to download
   * @param {number} [categoryId=0] - Category ID to assign (0 = default)
   * @returns {Promise<boolean>} True if the download was started successfully
   */
  async downloadSearchResult(fileHash, categoryId = 0) {
    if (DEBUG) console.log("[DEBUG] Requesting download ",fileHash," from search result with category", categoryId, "...");

    const children = categoryId !== 0 ? [
      {
        tagId: EC_TAGS.EC_TAG_PARTFILE_CAT,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT32,
        value: categoryId
      }
    ] : [];

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_PARTFILE,
        EC_TAG_TYPES.EC_TAGTYPE_HASH16,
        fileHash,
        children
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_DOWNLOAD_SEARCH_RESULT, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return response.opcode==6;
  }

  /**
   * Cancel and delete a download.
   * @param {string} fileHash - MD4 hash of the file to cancel
   * @returns {Promise<boolean>} True if the download was cancelled successfully
   */
  async cancelDownload(fileHash) {
    return this._sendFileCommand(EC_OPCODES.EC_OP_PARTFILE_DELETE, fileHash);
  }

  /**
   * Add a download via ed2k:// link.
   * @param {string} link - ed2k:// link
   * @param {number} [categoryId=0] - Category ID to assign (0 = default)
   * @returns {Promise<boolean>} True if the link was added successfully
   */
  async addEd2kLink(link, categoryId=0) {
    if (DEBUG) console.log("[DEBUG] Requesting ed2k link download ",link,"...");

    // Prepare request
    let children = [
      {
        tagId: EC_TAGS.EC_TAG_PARTFILE_CAT,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT32,  // Changed from UINT8 to UINT32
        value: categoryId
      }
    ];
    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_STRING,
        EC_TAG_TYPES.EC_TAGTYPE_STRING,
        link,
        children
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_ADD_LINK, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this._isSuccess(response);
  }

  /**
   * Pause a download.
   * @param {string} fileHash - MD4 hash of the file to pause
   * @returns {Promise<boolean>} True if the download was paused successfully
   */
  async pauseDownload(fileHash) {
    return this._sendFileCommand(EC_OPCODES.EC_OP_PARTFILE_PAUSE, fileHash);
  }

  /**
   * Resume a paused download.
   * @param {string} fileHash - MD4 hash of the file to resume
   * @returns {Promise<boolean>} True if the download was resumed successfully
   */
  async resumeDownload(fileHash) {
    return this._sendFileCommand(EC_OPCODES.EC_OP_PARTFILE_RESUME, fileHash);
  }

  /**
   * Get all aMule categories.
   * @returns {Promise<Object[]>} Array of category objects with { id, title, path, comment, color, priority }
   */
  async getCategories() {
    if (DEBUG) console.log("[DEBUG] Requesting categories...");

    // Request preferences with categories flag (as per aMule WebServer implementation)
    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_SELECT_PREFS,
        EC_TAG_TYPES.EC_TAGTYPE_UINT32,
        EC_PREFS.EC_PREFS_CATEGORIES
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_PREFERENCES, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    // Parse response - first tag is EC_TAG_PREFS_CATEGORIES container
    return this.parseCategories(response.tags);
  }

  /**
   * Read the core's shared-directory configuration.
   *
   * Replaces reading shareddir.dat off disk: aMule reports its two intent
   * lists, the explicitly shared roots and the recursively shared ones, and
   * does the subtree expansion itself.
   *
   * Requires a daemon advertising EC_TAG_CAN_SHAREDDIRS_CONFIG (aMule
   * ea20f8610, #530, in no release as of 3.0.1). Throws without sending
   * anything when it is absent — see {@link AmuleClient#_requireCapability}.
   *
   * @returns {Promise<Array<{ path: string, recursive: boolean }>>} One entry per
   *   configured root. `recursive` marks a root whose whole subtree is shared;
   *   the subdirectories it stands for are not listed individually.
   * @throws {Error} If the daemon did not advertise the capability
   */
  async getSharedDirs() {
    this._requireCapability(EC_TAG_CAN_SHAREDDIRS_CONFIG_NAME, 'getSharedDirs()');

    if (DEBUG) console.log("[DEBUG] Requesting shared directories...");

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_SHARED_DIRS, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return (response.tags || [])
      .filter(tag => tag.tagId === EC_TAGS.EC_TAG_SHAREDDIR)
      .map(tag => {
        const recursiveTag = tag.children?.find(c => c.tagId === EC_TAGS.EC_TAG_SHAREDDIR_RECURSIVE);
        return {
          path: tag.humanValue,
          // Present only on recursive roots, so absence is the common case.
          recursive: recursiveTag !== undefined && recursiveTag.humanValue !== 0
        };
      });
  }

  /**
   * Replace the core's shared-directory configuration.
   *
   * REPLACES, does not merge: whatever is not in `dirs` stops being shared, and
   * passing an empty array unshares everything. Read the current list with
   * {@link AmuleClient#getSharedDirs} first if you mean to add to it.
   *
   * Validation is per path and the result is partial: aMule applies every path
   * that validated and reports the others individually. So an empty `rejected`
   * means everything was taken, and a non-empty one does NOT mean nothing was —
   * `success` says the daemon accepted and persisted the request, not that every
   * path in it survived.
   *
   * The reply means "saved", not "rescan finished": aMule writes both intent
   * files synchronously but defers the rescan to its next Process() tick, so do
   * not poll the shared-file list expecting it to have changed already.
   *
   * Requires a daemon advertising EC_TAG_CAN_SHAREDDIRS_CONFIG. Throws without
   * sending anything when it is absent.
   *
   * @param {Array<string|{ path: string, recursive?: boolean }>} dirs - Roots to
   *   share. A bare string is shared non-recursively.
   * @returns {Promise<{ success: boolean, rejected: Array<{ path: string, error: number }> }>}
   *   `error` is an {@link AmuleClient.SHAREDDIR_ERROR} code — a number, never a
   *   sentence, so the daemon's locale cannot leak into the caller's UI.
   * @throws {Error} If the daemon did not advertise the capability, or `dirs` is
   *   not an array of usable paths
   */
  async setSharedDirs(dirs) {
    this._requireCapability(EC_TAG_CAN_SHAREDDIRS_CONFIG_NAME, 'setSharedDirs()');

    if (!Array.isArray(dirs)) {
      throw new TypeError('setSharedDirs() expects an array of paths');
    }

    const reqTags = dirs.map((entry, i) => {
      const path = typeof entry === 'string' ? entry : entry?.path;
      const recursive = typeof entry === 'string' ? false : Boolean(entry?.recursive);
      if (typeof path !== 'string' || path === '') {
        // Refuse rather than send a blank the daemon would reject anyway: the
        // caller's bug is clearer here than in a rejection list.
        throw new TypeError(`setSharedDirs(): entry ${i} has no usable path`);
      }
      const children = recursive
        ? [{
            tagId: EC_TAGS.EC_TAG_SHAREDDIR_RECURSIVE,
            tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT8,
            value: 1
          }]
        : [];
      return this.session.createTag(
        EC_TAGS.EC_TAG_SHAREDDIR,
        EC_TAG_TYPES.EC_TAGTYPE_STRING,
        path,
        children
      );
    });

    if (DEBUG) console.log("[DEBUG] Setting shared directories:", dirs.length);

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SET_SHARED_DIRS, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    const rejected = (response.tags || [])
      .filter(tag => tag.tagId === EC_TAGS.EC_TAG_SHAREDDIR_REJECTED)
      .map(tag => {
        const errorTag = tag.children?.find(c => c.tagId === EC_TAGS.EC_TAG_SHAREDDIR_ERROR);
        return {
          path: tag.humanValue,
          error: typeof errorTag?.humanValue === 'number' ? errorTag.humanValue : null
        };
      });

    return {
      success: response.opcode === EC_OPCODES.EC_OP_SET_SHARED_DIRS,
      rejected
    };
  }

  /**
   * Create a new category in aMule.
   * @param {string} title - Category name
   * @param {string} [path=''] - Download path for this category
   * @param {string} [comment=''] - Category comment
   * @param {number} [color=0] - Category color in RGB format (0xRRGGBB)
   * @param {number} [priority=0] - Download priority for this category
   * @returns {Promise<{ success: boolean, categoryId: number|null, applied: 'full'|'partial'|'none', reason: string|null, message: string|null, keptPath: string|null }>}
   *   `success` is true when the category exists afterwards, which includes the
   *   case where aMule refused the download path: it still creates the category
   *   and falls back to the incoming directory. `applied` tells the two apart —
   *   'full' when the path was taken, 'partial' when it was not, with `reason`
   *   set to 'path_rejected' and `keptPath` holding the directory aMule used.
   *   `categoryId` is only sent by aMule on the 'partial' reply; a clean create
   *   answers with a bare EC_OP_NOOP and it stays null. Read back the list with
   *   {@link AmuleClient#getCategories} if the caller needs the id either way.
   */
  async createCategory(title, path = '', comment = '', color = 0, priority = 0) {
    if (DEBUG) console.log("[DEBUG] Creating category:", title);

    const children = [
      {
        tagId: EC_TAGS.EC_TAG_CATEGORY_TITLE,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_STRING,
        value: title
      },
      {
        tagId: EC_TAGS.EC_TAG_CATEGORY_PATH,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_STRING,
        value: path
      },
      {
        tagId: EC_TAGS.EC_TAG_CATEGORY_COMMENT,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_STRING,
        value: comment
      },
      {
        tagId: EC_TAGS.EC_TAG_CATEGORY_COLOR,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT32,
        value: color  // RGB format: 0xRRGGBB
      },
      {
        tagId: EC_TAGS.EC_TAG_CATEGORY_PRIO,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT8,
        value: priority
      }
    ];

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_CATEGORY,
        EC_TAG_TYPES.EC_TAGTYPE_CUSTOM,
        undefined,  // No value for container tag
        children
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_CREATE_CATEGORY, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    const result = this._parseCategoryResult(response);

    if (DEBUG) console.log("[DEBUG] Category creation result:", result, "opcode:", response.opcode);

    return result;
  }

  /**
   * Update an existing category in aMule.
   * @param {number} categoryId - Category ID to update
   * @param {string} title - Category name
   * @param {string} path - Download path
   * @param {string} comment - Category comment
   * @param {number} color - Category color in RGB format (0xRRGGBB)
   * @param {number} priority - Download priority
   * @returns {Promise<{ success: boolean, applied: 'full'|'partial'|'none', reason: string|null, message: string|null, keptPath: string|null }>}
   *   `applied` is 'full' when aMule took every field, 'partial' when it stored
   *   the title, comment, colour and priority but refused the path — `reason`
   *   is then 'path_rejected' and `keptPath` holds the path it kept, and this
   *   still counts as `success: true` because the update did land — and 'none'
   *   when nothing was applied, with `reason` 'no_such_category' for an index
   *   past the end of the list. `message` is aMule's own text when it sends
   *   any, verbatim and in the daemon's locale, so log it rather than match it.
   *
   *   NOTE: this used to resolve to a bare boolean. An object is always truthy,
   *   so every caller testing the result directly has to be updated with it.
   */
  async updateCategory(categoryId, title, path, comment, color, priority) {
    if (DEBUG) console.log("[DEBUG] Updating category:", categoryId);

    const children = [
      {
        tagId: EC_TAGS.EC_TAG_CATEGORY_TITLE,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_STRING,
        value: title
      },
      {
        tagId: EC_TAGS.EC_TAG_CATEGORY_PATH,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_STRING,
        value: path
      },
      {
        tagId: EC_TAGS.EC_TAG_CATEGORY_COMMENT,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_STRING,
        value: comment
      },
      {
        tagId: EC_TAGS.EC_TAG_CATEGORY_COLOR,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT32,
        value: color
      },
      {
        tagId: EC_TAGS.EC_TAG_CATEGORY_PRIO,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT8,
        value: priority
      }
    ];

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_CATEGORY,
        EC_TAG_TYPES.EC_TAGTYPE_UINT32,  // Category ID is uint32
        categoryId,
        children
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_UPDATE_CATEGORY, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this._parseCategoryResult(response);
  }

  /**
   * Delete a category from aMule.
   *
   * @param {number} categoryId - Category ID to delete
   * @returns {Promise<{ success: boolean, applied: 'full'|'none', reason: string|null, message: string|null }>}
   *   `applied` is 'full' when the category is gone and 'none' when aMule
   *   discarded the request, with `reason` naming which guard refused it:
   *   'default_category' for index 0, 'no_such_category' for an index past the
   *   end of the list, 'malformed_request' when it could not read an index at
   *   all. There is no 'partial' — a delete either happened or did not — and no
   *   `keptPath`, which aMule deliberately never sends for a delete. `message`
   *   is aMule's own English text when it sends any.
   *
   *   Against a core predating amule-org/amule#1232 every delete answers
   *   EC_OP_NOOP, so a discarded one still reports 'full'; see
   *   {@link AmuleClient#_parseCategoryDeleteResult}.
   *
   *   NOTE: this used to resolve to a bare boolean. An object is always truthy,
   *   so every caller testing the result directly has to be updated with it.
   */
  async deleteCategory(categoryId) {
    if (DEBUG) console.log("[DEBUG] Deleting category:", categoryId);

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_CATEGORY,
        EC_TAG_TYPES.EC_TAGTYPE_UINT32,
        categoryId
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_DELETE_CATEGORY, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this._parseCategoryDeleteResult(response);
  }

  /**
   * Assign a download to a category.
   * @param {string} fileHash - MD4 hash of the file
   * @param {number} categoryId - Category ID to assign
   * @returns {Promise<boolean>} True if the category was set successfully
   */
  async setFileCategory(fileHash, categoryId) {
    if (DEBUG) console.log("[DEBUG] Setting file category:", fileHash, "->", categoryId);

    const children = [
      {
        tagId: EC_TAGS.EC_TAG_PARTFILE_CAT,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT32,  // Category ID is uint32
        value: categoryId
      }
    ];

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_PARTFILE,
        EC_TAG_TYPES.EC_TAGTYPE_HASH16,
        fileHash,
        children
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_PARTFILE_SET_CAT, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this._isSuccess(response);
  }

  /**
   * Rename a file (download or shared).
   * Searches the download queue first, then known (shared) files.
   * @param {string} fileHash - MD4 hash of the file to rename
   * @param {string} newName - New filename
   * @returns {Promise<{ success: boolean, error?: string }>} Result with optional error message
   */
  async renameFile(fileHash, newName) {
    if (DEBUG) console.log("[DEBUG] Renaming file:", fileHash, "->", newName);

    // As per aMule source (ExternalConn.cpp): EC_OP_RENAME_FILE expects
    // EC_TAG_KNOWNFILE (hash) + EC_TAG_PARTFILE_NAME (new name) as top-level tags.
    // It searches download queue first, then known files.
    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_KNOWNFILE,
        EC_TAG_TYPES.EC_TAGTYPE_HASH16,
        fileHash
      ),
      this.session.createTag(
        EC_TAGS.EC_TAG_PARTFILE_NAME,
        EC_TAG_TYPES.EC_TAGTYPE_STRING,
        newName
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_RENAME_FILE, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    if (response.opcode === EC_OPCODES.EC_OP_FAILED) {
      const errorMsg = response.tags?.find(t => t.tagId === EC_TAGS.EC_TAG_STRING)?.humanValue;
      return { success: false, error: errorMsg || 'Rename failed' };
    }

    return { success: this._isSuccess(response) };
  }

  /**
   * Set the comment and rating on a shared file.
   *
   * aMule's EC handler always writes both fields together — missing tags are
   * treated as "clear" (empty comment / zero rating). To update only one field
   * while preserving the other, read the current values via getSharedFiles()
   * first and re-supply the unchanged one here.
   *
   * Rating scale: 0 = Not rated, 1 = Fake, 2 = Poor, 3 = Fair, 4 = Good, 5 = Excellent
   *
   * @param {string} fileHash - MD4 hash of the shared file
   * @param {string} comment - Comment text (empty string clears)
   * @param {number} rating - Rating 0–5 (0 = not rated)
   * @returns {Promise<boolean>} True if the command was accepted
   */
  async setFileRatingComment(fileHash, comment, rating) {
    if (typeof comment !== 'string') {
      throw new TypeError('setFileRatingComment: comment must be a string');
    }
    if (!Number.isInteger(rating) || rating < 0 || rating > 5) {
      throw new RangeError('setFileRatingComment: rating must be an integer between 0 and 5');
    }

    if (DEBUG) console.log("[DEBUG] Setting comment/rating for file:", fileHash, comment, rating);

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_KNOWNFILE,
        EC_TAG_TYPES.EC_TAGTYPE_HASH16,
        fileHash
      ),
      this.session.createTag(
        EC_TAGS.EC_TAG_KNOWNFILE_COMMENT,
        EC_TAG_TYPES.EC_TAGTYPE_STRING,
        comment
      ),
      this.session.createTag(
        EC_TAGS.EC_TAG_KNOWNFILE_RATING,
        EC_TAG_TYPES.EC_TAGTYPE_UINT8,
        rating
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SHARED_FILE_SET_COMMENT, reqTags);

    if (DEBUG) console.log("[DEBUG] setFileRatingComment response:", response);

    return this._isSuccess(response);
  }

  /**
   * Decide which tracked ECIDs a getUpdate() reply removes.
   *
   * The two protocols are opposites and the choice is not ours to make — it is
   * whichever the daemon confirmed at auth:
   *
   *   legacy (no EC_TAG_CAN_PARTIAL_UPDATE echo, e.g. aMule 2.3.3)
   *     Every live object is present in every reply, unchanged ones as a
   *     5-byte alive marker, so absence means the object is gone.
   *
   *   partial (echo present)
   *     Unchanged objects are omitted entirely, so absence means "no change"
   *     and only an explicit EC_TAG_FILE_REMOVED means gone. Deleting on
   *     absence here would drop every unchanged object on every poll.
   *
   * @param {Object} response - Raw EC response
   * @param {Set<number>} seen - ECIDs present in this reply
   * @param {Iterable<number>} tracked - ECIDs currently held in state
   * @returns {number[]} ECIDs to drop
   * @private
   */
  _removedEcids(response, seen, tracked) {
    if (this.hasCapability('EC_TAG_CAN_PARTIAL_UPDATE')) {
      const removed = [];
      for (const tag of response.tags || []) {
        if (tag.tagId !== EC_TAGS.EC_TAG_FILE_REMOVED) continue;
        const ecid = this._tagOwnId(tag);
        if (ecid !== null) removed.push(ecid);
      }
      return removed;
    }
    return [...tracked].filter(ecid => !seen.has(ecid));
  }

  /**
   * Read a tag's own value as an ECID.
   *
   * Separate from _parseDownloadFields(), which walks only tag.children: the
   * ECID is the tag's own value, so that walk can never see it.
   *
   * @param {Object} tag - Raw EC tag
   * @returns {number|null} The ECID, or null if the tag carries no numeric value
   * @private
   */
  _tagOwnId(tag) {
    // Not `humanValue || value`: an ECID of 0 would fall through to null.
    let id = tag?.humanValue !== undefined ? tag.humanValue : tag?.value;
    if (Buffer.isBuffer(id)) id = (id.length > 0 && id.length <= 6) ? id.readUIntBE(0, id.length) : null;
    return typeof id === 'number' ? id : null;
  }

  /**
   * Parse fields from an EC_TAG_PARTFILE tag (for incremental merging).
   * Only returns fields actually present in the response.
   * @param {Object} tag - Raw EC tag
   * @returns {Object} Parsed download fields
   * @private
   */
  _parseDownloadFields(tag) {
    const result = {};
    if (!tag.children) return result;

    for (const sub of tag.children) {
      const val = sub.humanValue;
      switch (sub.tagId) {
        case EC_TAGS.EC_TAG_PARTFILE_NAME:                    result.fileName = fixMojibake(val); result.rawFileName = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_HASH:                    result.fileHash = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_STATUS:                  result.status = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_SIZE_FULL:               result.fileSize = Number(val); break;
        case EC_TAGS.EC_TAG_PARTFILE_SIZE_DONE:               result.fileSizeDownloaded = Number(val); break;
        case EC_TAGS.EC_TAG_PARTFILE_SPEED:                   result.speed = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_SOURCE_COUNT:            result.sourceCount = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_SOURCE_COUNT_XFER:       result.sourceCountXfer = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_SOURCE_COUNT_A4AF:       result.sourceCountA4AF = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_SOURCE_COUNT_NOT_CURRENT: result.sourceCountNotCurrent = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_PRIO:                    result.priority = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_CAT:                     result.category = val || 0; break;
        case EC_TAGS.EC_TAG_PARTFILE_LAST_SEEN_COMP:          result.lastSeenComplete = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_ED2K_LINK:               result.ed2kLink = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_SHARED:                   result.isShared = val === 1; break;
        case EC_TAGS.EC_TAG_PARTFILE_PART_STATUS:             result._rawPartStatus = sub.value; break;
        case EC_TAGS.EC_TAG_PARTFILE_GAP_STATUS:              result._rawGapStatus = sub.value; break;
        case EC_TAGS.EC_TAG_PARTFILE_REQ_STATUS:              result._rawReqStatus = sub.value; break;
        // Aggregated user rating for search results (requires aMule PR #452
        // https://github.com/amule-project/amule/pull/452). aMule builds without
        // that patch don't emit this tag and the case simply never fires.
        case EC_TAGS.EC_TAG_KNOWNFILE_RATING:                 result.rating = val || 0; break;
        // Search-result grouping: the ECID of the result this one hangs under.
        // Emitted only when the file has a parent, so absence means "parent",
        // and only when the caller opted in -- see getSearchResults(). Never
        // appears on an EC_TAG_PARTFILE, so downloads are unaffected, and never
        // on an EC_DETAIL_UPDATE reply either: ECSpecialCoreTags.cpp returns
        // before adding it, so getUpdate() will not see this field.
        case EC_TAGS.EC_TAG_SEARCH_PARENT:                    result.parentId = val; break;
      }
    }

    // Calculate progress when both size fields are present
    if (result.fileSizeDownloaded !== undefined && result.fileSize !== undefined && result.fileSize > 0) {
      result.progress = ((result.fileSizeDownloaded / result.fileSize) * 100).toFixed(2);
    }

    return result;
  }

  /**
   * Reconstruct EC buffer fields (partStatus, gapStatus, reqStatus) for a download.
   * aMule's EC_OP_GET_UPDATE sends RLE-compressed XOR diffs for these fields.
   * We must: RLE-decode → XOR with previous state → store → decode to usable format.
   * @param {number} ecid - Download ECID for state tracking
   * @param {Object} fields - Parsed fields from _parseDownloadFields (may contain _raw* fields)
   * @private
   */
  _reconstructBufferFields(ecid, fields) {
    if (!this._ecBufferState) this._ecBufferState = new Map();

    const FIELDS = [
      { raw: '_rawPartStatus', out: 'partStatus', uint64: false },
      { raw: '_rawGapStatus',  out: 'gapStatus',  uint64: true },
      { raw: '_rawReqStatus',  out: 'reqStatus',   uint64: true },
    ];

    for (const { raw, out, uint64 } of FIELDS) {
      if (!fields[raw]) continue;

      // Step 1: RLE-decode the incoming buffer
      const decoded = AmuleClient._decodeRLE(fields[raw]);

      // Step 2: XOR-reconstruct with previous state
      // Mirrors aMule's RLE_Data exactly:
      //   1. Realloc(newSize) — resize m_buff to match incoming size
      //      (preserves overlap, zero-extends on grow, truncates on shrink)
      //   2. m_buff[k] ^= decBuf[k] — XOR diff onto resized prev
      //
      // IMPORTANT: The data is stored in column-major (interleaved) order.
      // aMule's Realloc operates on the raw interleaved bytes — it does NOT
      // de-interleave before resizing. This means on size change, the column
      // stride changes and the overlapping bytes represent different logical
      // positions. aMule's own code does this too, so we match it exactly.
      const state = this._ecBufferState.get(ecid) || {};
      const prev = state[out];
      let current;
      let xorApplied = false;
      if (prev) {
        // Realloc: resize prev to decoded.length (same as aMule's Realloc)
        let resized;
        if (prev.length === decoded.length) {
          resized = Buffer.from(prev); // copy — don't mutate stored state
        } else if (decoded.length > prev.length) {
          // Grow: copy old data, zero-fill extension
          resized = Buffer.alloc(decoded.length, 0);
          prev.copy(resized, 0, 0, prev.length);
        } else {
          // Shrink: truncate to new size
          resized = Buffer.from(prev.subarray(0, decoded.length));
        }
        // XOR: resized[k] ^= decoded[k] (same as aMule: m_buff[k] ^= decBuf[k])
        for (let i = 0; i < decoded.length; i++) {
          resized[i] ^= decoded[i];
        }
        current = resized;
        xorApplied = true;
      } else {
        // First update — no previous state, decoded IS the full data
        current = decoded;
      }

      if (DEBUG) {
        const nonZeroDecoded = Array.from(decoded).filter(b => b !== 0).length;
        const nonZeroCurrent = Array.from(current).filter(b => b !== 0).length;
        console.log(`[EC-RECONSTRUCT] ecid=${ecid} field=${out}: raw=${fields[raw].length}B → rle=${decoded.length}B → xor=${xorApplied} (prev=${prev ? prev.length + 'B' : 'none'}) → current=${current.length}B (nonzero: decoded=${nonZeroDecoded}, current=${nonZeroCurrent})`);
      }

      // Step 3: Store reconstructed interleaved bytes for next XOR
      state[out] = current;
      this._ecBufferState.set(ecid, state);

      // Step 4: Decode to usable format
      if (uint64) {
        fields[out] = AmuleClient._decodeInterleavedUint64Pairs(current);
      } else {
        // partStatus: each byte is a source count
        fields[out] = Array.from(current);
      }

      // Clean up raw field
      delete fields[raw];
    }
  }

  /**
   * Decode RLE-compressed buffer (aMule EC protocol format).
   * Format: [value, value, count] = repeat value count times; single values pass through.
   * @param {Buffer} buff - RLE-encoded buffer
   * @returns {Buffer} Decoded buffer
   * @static
   */
  static _decodeRLE(buff) {
    if (!buff || buff.length === 0) return Buffer.alloc(0);

    // First pass: calculate output size
    let outputSize = 0;
    let i = 0;
    while (i < buff.length) {
      if (i + 1 < buff.length && buff[i + 1] === buff[i]) {
        if (i + 2 < buff.length) {
          outputSize += buff[i + 2];
          i += 3;
        } else {
          outputSize += 2;
          i += 2;
        }
      } else {
        outputSize++;
        i++;
      }
    }

    // Second pass: decode
    const output = Buffer.alloc(outputSize);
    let outIdx = 0;
    i = 0;
    while (i < buff.length) {
      if (i + 1 < buff.length && buff[i + 1] === buff[i]) {
        if (i + 2 < buff.length) {
          const val = buff[i];
          const count = buff[i + 2];
          output.fill(val, outIdx, outIdx + count);
          outIdx += count;
          i += 3;
        } else {
          output[outIdx++] = buff[i];
          output[outIdx++] = buff[i + 1];
          i += 2;
        }
      } else {
        output[outIdx++] = buff[i];
        i++;
      }
    }

    return output;
  }

  /**
   * Decode interleaved column-major bytes into uint64 pairs [{start, end}].
   * aMule stores uint64 values as byte-interleaved columns for better RLE compression.
   * @param {Buffer} buf - Interleaved byte buffer
   * @returns {Array<{start: number, end: number}>} Array of range pairs
   * @static
   */
  static _decodeInterleavedUint64Pairs(buf) {
    const numValues = Math.floor(buf.length / 8);
    if (numValues === 0) return [];

    const values = new Array(numValues);
    for (let i = 0; i < numValues; i++) {
      let value = 0n;
      for (let j = 0; j < 8; j++) {
        const byteIdx = i + j * numValues;
        if (byteIdx < buf.length) {
          // Little-endian: byte 0 is LSB, byte 7 is MSB
          value |= BigInt(buf[byteIdx]) << BigInt(j * 8);
        }
      }
      values[i] = Number(value);
    }

    // Pair up as (start, end) ranges
    const ranges = [];
    for (let i = 0; i < values.length; i += 2) {
      if (i + 1 < values.length) {
        ranges.push({ start: values[i], end: values[i + 1] });
      }
    }
    return ranges;
  }

  /**
   * Parse fields from an EC_TAG_KNOWNFILE tag (for incremental merging).
   * Only returns fields actually present in the response.
   * @param {Object} tag - Raw EC tag
   * @returns {{fileName: string, fileHash: string, fileSize: number, transferred: number, transferredTotal: number, reqCount: number, reqCountTotal: number, acceptedCount: number, acceptedCountTotal: number, priority: number, path: string, completeSources: number, onQueue: number, ed2kLink: string, comment: string, rating: number}[]} Parsed shared file fields
   * @private
   */
  _parseSharedFileFields(tag) {
    const result = {};
    if (!tag.children) return result;

    for (const sub of tag.children) {
      const val = sub.humanValue;
      switch (sub.tagId) {
        case EC_TAGS.EC_TAG_PARTFILE_NAME:               result.fileName = fixMojibake(val); result.rawFileName = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_HASH:               result.fileHash = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_SIZE_FULL:          result.fileSize = Number(val); break;
        case EC_TAGS.EC_TAG_KNOWNFILE_XFERRED:           result.transferred = Number(val); break;
        case EC_TAGS.EC_TAG_KNOWNFILE_XFERRED_ALL:       result.transferredTotal = Number(val); break;
        case EC_TAGS.EC_TAG_KNOWNFILE_REQ_COUNT:         result.reqCount = val; break;
        case EC_TAGS.EC_TAG_KNOWNFILE_REQ_COUNT_ALL:     result.reqCountTotal = val; break;
        case EC_TAGS.EC_TAG_KNOWNFILE_ACCEPT_COUNT:      result.acceptedCount = val; break;
        case EC_TAGS.EC_TAG_KNOWNFILE_ACCEPT_COUNT_ALL:  result.acceptedCountTotal = val; break;
        case EC_TAGS.EC_TAG_KNOWNFILE_PRIO:              result.priority = val; break;
        case EC_TAGS.EC_TAG_KNOWNFILE_FILENAME:          result.path = val; break;
        case EC_TAGS.EC_TAG_KNOWNFILE_COMPLETE_SOURCES:  result.completeSources = val; break;
        case EC_TAGS.EC_TAG_KNOWNFILE_ON_QUEUE:          result.onQueue = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_ED2K_LINK:          result.ed2kLink = val; break;
        case EC_TAGS.EC_TAG_KNOWNFILE_COMMENT:           result.comment = val || ''; break;
        case EC_TAGS.EC_TAG_KNOWNFILE_RATING:            result.rating = val || 0; break;
      }
    }

    return result;
  }

  /**
   * Parse fields from an EC_TAG_CLIENT tag (for incremental merging).
   * Only returns fields actually present in the response.
   * @param {Object} clientTag - Raw EC tag
   * @returns {Object} Parsed client/peer fields
   * @private
   */
  _parseClientFields(clientTag) {
    const result = {};
    if (!clientTag.children) return result;

    for (const sub of clientTag.children) {
      const val = sub.humanValue;
      switch (sub.tagId) {
        case EC_TAGS.EC_TAG_CLIENT_NAME:           result.userName = val || ''; break;
        case EC_TAGS.EC_TAG_CLIENT_HASH:            result.userHash = val; break;
        case EC_TAGS.EC_TAG_CLIENT_REQUEST_FILE:    result.requestFileEcid = val; break;
        case EC_TAGS.EC_TAG_CLIENT_UPLOAD_FILE:     result.uploadFileEcid = val; break;
        case EC_TAGS.EC_TAG_CLIENT_SOFTWARE:        result.software = val; break;
        case EC_TAGS.EC_TAG_CLIENT_SOFT_VER_STR:    result.softwareVersion = val; break;
        case EC_TAGS.EC_TAG_CLIENT_DOWNLOAD_STATE:  result.downloadState = val; break;
        case EC_TAGS.EC_TAG_CLIENT_UPLOAD_STATE:    result.uploadState = val; break;
        // DOWN_SPEED is returned as float in KB/s, UP_SPEED as integer in B/s
        // Normalize both to bytes/sec for consistent handling
        case EC_TAGS.EC_TAG_CLIENT_DOWN_SPEED:      result.downSpeed = ((val || 0) * 1024) | 0; break;
        case EC_TAGS.EC_TAG_CLIENT_UP_SPEED:        result.upSpeed = val || 0; break;
        case EC_TAGS.EC_TAG_CLIENT_DOWNLOAD_TOTAL:  result.downloadTotal = val || 0; break;
        case EC_TAGS.EC_TAG_CLIENT_UPLOAD_TOTAL:    result.uploadTotal = val || 0; break;
        case EC_TAGS.EC_TAG_CLIENT_USER_IP:
          // Convert 32-bit little-endian integer to dotted notation
          if (typeof val === 'number' && val > 0) {
            result.ip = `${val & 0xFF}.${(val >>> 8) & 0xFF}.${(val >>> 16) & 0xFF}.${(val >>> 24) & 0xFF}`;
          } else {
            result.ip = val;
          }
          break;
        case EC_TAGS.EC_TAG_CLIENT_USER_PORT:       result.port = val; break;
        case EC_TAGS.EC_TAG_CLIENT_FROM:            result.sourceFrom = val; break;
        case EC_TAGS.EC_TAG_CLIENT_REMOTE_QUEUE_RANK: result.remoteQueueRank = val; break;
        case EC_TAGS.EC_TAG_CLIENT_REMOTE_FILENAME: result.remoteFilename = val; break;
        case EC_TAGS.EC_TAG_CLIENT_SCORE:           result.score = val; break;
        case EC_TAGS.EC_TAG_CLIENT_IDENT_STATE:     result.identState = val; break;
        case EC_TAGS.EC_TAG_CLIENT_OBFUSCATION_STATUS: result.obfuscation = val; break;
        case EC_TAGS.EC_TAG_CLIENT_PART_STATUS:     result.partStatus = sub.value; break;
        case EC_TAGS.EC_TAG_CLIENT_UPLOAD_PART_STATUS: result.uploadPartStatus = sub.value; break;
        case EC_TAGS.EC_TAG_CLIENT_AVAILABLE_PARTS: result.availableParts = val; break;
        case EC_TAGS.EC_TAG_CLIENT_SERVER_NAME:     result.serverName = val; break;
        case EC_TAGS.EC_TAG_CLIENT_SERVER_IP:
          if (typeof val === 'number' && val > 0) {
            result.serverIP = `${val & 0xFF}.${(val >>> 8) & 0xFF}.${(val >>> 16) & 0xFF}.${(val >>> 24) & 0xFF}`;
          } else {
            result.serverIP = val;
          }
          break;
        case EC_TAGS.EC_TAG_CLIENT_SERVER_PORT:     result.serverPort = val; break;
        case EC_TAGS.EC_TAG_CLIENT_MOD_VERSION:     result.modVersion = val; break;
        case EC_TAGS.EC_TAG_CLIENT_OS_INFO:         result.osInfo = val; break;
        case EC_TAGS.EC_TAG_CLIENT_KAD_PORT:        result.kadPort = val; break;
        case EC_TAGS.EC_TAG_PARTFILE_NAME:          result.transferFileName = fixMojibake(val); break;
        case EC_TAGS.EC_TAG_PARTFILE_SIZE_XFER:     result.transferredSession = val; break;
        case EC_TAGS.EC_TAG_CLIENT_UPLOAD_SESSION:  result.uploadSession = val; break;
      }
    }

    return result;
  }



  /**
   * Parse category tags from an EC_OP_GET_PREFERENCES response.
   * @param {Object[]} tags - Raw response tags
   * @returns {Object[]} Array of category objects with { id, title, path, comment, color, priority }
   */
  parseCategories(tags) {
    // As per aMule source: first tag is EC_TAG_PREFS_CATEGORIES container
    const prefsTag = tags[0];

    // Check if we have any tags at all (empty response means no categories)
    if (!tags || tags.length === 0) {
      return [];
    }

    // Check if it's the categories tag
    if (!prefsTag || prefsTag.tagId !== EC_TAGS.EC_TAG_PREFS_CATEGORIES) {
      if (DEBUG) console.warn('Expected EC_TAG_PREFS_CATEGORIES but got:', prefsTag?.tagId);
      return [];
    }

    if (!prefsTag.children || prefsTag.children.length === 0) {
      return [];  // No categories defined
    }

    // Each child is EC_TAG_CATEGORY with ID as value and properties as children
    return prefsTag.children
      .filter(t => t.tagId === EC_TAGS.EC_TAG_CATEGORY)
      .map((catTag, index) => {
        // Category ID from tag value - handle both Buffer and number types
        let id = catTag.humanValue || catTag.value || index;
        if (Buffer.isBuffer(id)) {
          id = id.readUInt8(0);  // Convert Buffer to number
        }

        const title = catTag.children?.find(c => c.tagId === EC_TAGS.EC_TAG_CATEGORY_TITLE)?.humanValue || '';
        const path = catTag.children?.find(c => c.tagId === EC_TAGS.EC_TAG_CATEGORY_PATH)?.humanValue || '';
        const comment = catTag.children?.find(c => c.tagId === EC_TAGS.EC_TAG_CATEGORY_COMMENT)?.humanValue || '';
        const color = catTag.children?.find(c => c.tagId === EC_TAGS.EC_TAG_CATEGORY_COLOR)?.humanValue || 0;
        const priority = catTag.children?.find(c => c.tagId === EC_TAGS.EC_TAG_CATEGORY_PRIO)?.humanValue || 0;

        return { id, title, path, comment, color, priority };
      });
  }

  /**
   * Extract the new category ID from an EC_OP_CREATE_CATEGORY response.
   * @param {Object} response - Raw EC response
   * @returns {number|null} The new category ID, or null if not found
   */
  parseCategoryIdFromResponse(response) {
    const categoryTag = response.tags?.find(t => t.tagId === EC_TAGS.EC_TAG_CATEGORY);
    if (!categoryTag) return null;

    // Not `humanValue || value`: category 0 is a real id and would fall through
    // to null. aMule sizes the tag to the value, so it arrives as UINT8/16/32.
    let id = categoryTag.humanValue !== undefined ? categoryTag.humanValue : categoryTag.value;
    // readUIntBE tops out at 6 bytes; a category id never needs more than 4.
    if (Buffer.isBuffer(id)) id = (id.length > 0 && id.length <= 6) ? id.readUIntBE(0, id.length) : null;
    return typeof id === 'number' ? id : null;
  }

  /**
   * Format a raw EC value into a human-readable string.
   * @param {*} value - Raw value to format
   * @param {number} type - EC_VALUE_TYPE constant
   * @returns {string|*} Formatted string or original value
   */
  formatValue(value, type) {
    if (value === undefined || value === null) return value;
    
    switch (type) {
      case EC_VALUE_TYPE.EC_VALUE_BYTES: {
        // Convert bytes to human-readable format
        const num = typeof value === 'string' ? BigInt(value) : BigInt(value);
        const bytes = Number(num);
        
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
        if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
        return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
      }
      
      case EC_VALUE_TYPE.EC_VALUE_SPEED: {
        // Convert bytes/s to KB/s
        const kbps = value / 1024;
        return `${kbps.toFixed(2)} KB/s`;
      }
      
      case EC_VALUE_TYPE.EC_VALUE_TIME: {
        // Convert seconds to days + hours + minutes
        const seconds = Number(value);
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        
        const parts = [];
        if (days > 0) parts.push(`${days}d`);
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}m`);
        if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);
        
        return parts.join(' ');
      }
      
      case EC_VALUE_TYPE.EC_VALUE_DOUBLE:
        return typeof value === 'number' ? value.toFixed(2) : value;
      
      case EC_VALUE_TYPE.EC_VALUE_INTEGER:
      case EC_VALUE_TYPE.EC_VALUE_ISTRING:
      case EC_VALUE_TYPE.EC_VALUE_ISHORT:
      case EC_VALUE_TYPE.EC_VALUE_STRING:
      default:
        return value;
    }
  }

  /**
   * Deep merge for raw tag trees from incremental EC updates.
   *
   * aMule's EC protocol sends only changed fields in incremental updates
   * (EC_DETAIL_INC_UPDATE). For nested structures like EC_TAG_PARTFILE_SOURCE_NAMES,
   * the server uses an ID-based diff: each entry is identified by a numeric ID
   * (stored as _value by buildTagTree). Count-only updates omit the filename string,
   * expecting the client to preserve it from the initial full response.
   *
   * This merge handles:
   * - Objects: recursively merged (unchanged fields preserved)
   * - Arrays of objects with _value (ID-keyed): merged by matching _value,
   *   entries with count=0 are removals (aMule protocol convention)
   * - Other arrays / primitives: replaced outright
   */
  deepMergeRaw(existing, updates) {
    const result = { ...existing };
    for (const key of Object.keys(updates)) {
      let newVal = updates[key];
      let oldVal = result[key];

      // Normalize: when one side is an array and the other a single ID-keyed object,
      // wrap the single object so both sides are arrays (buildTagTree produces a
      // single object when there's one entry, an array when there are multiple).
      if (oldVal && newVal && typeof newVal === 'object' && typeof oldVal === 'object') {
        const newIsIdObj = !Array.isArray(newVal) && '_value' in newVal;
        const oldIsIdObj = !Array.isArray(oldVal) && '_value' in oldVal;
        if (oldIsIdObj && newIsIdObj) { oldVal = [oldVal]; newVal = [newVal]; }
        else if (Array.isArray(oldVal) && newIsIdObj) newVal = [newVal];
        else if (oldIsIdObj && Array.isArray(newVal)) oldVal = [oldVal];
      }

      if (Array.isArray(newVal) && Array.isArray(oldVal) && newVal.length > 0 &&
          typeof newVal[0] === 'object' && newVal[0] !== null && '_value' in newVal[0]) {
        // ID-keyed array merge (matches aMule's CPartFile_Encoder behaviour)
        const oldMap = new Map();
        for (const entry of oldVal) {
          if (entry && entry._value !== undefined) oldMap.set(entry._value, entry);
        }
        for (const entry of newVal) {
          const id = entry._value;
          const prev = oldMap.get(id);
          if (prev) {
            oldMap.set(id, this.deepMergeRaw(prev, entry));
          } else {
            oldMap.set(id, entry);
          }
        }
        // Filter out entries where the server signalled removal (count = 0)
        const countKey = key + '_COUNTS';
        result[key] = [...oldMap.values()].filter(e =>
          e[countKey] === undefined || e[countKey] !== 0
        );
      } else if (
        newVal && typeof newVal === 'object' && !Array.isArray(newVal) &&
        oldVal && typeof oldVal === 'object' && !Array.isArray(oldVal)
      ) {
        result[key] = this.deepMergeRaw(oldVal, newVal);
      } else {
        result[key] = newVal;
      }
    }
    return result;
  }

  /**
   * Build a nested JS object tree from raw EC tags.
   * Handles duplicate keys by converting to arrays, and attaches
   * formatted values via EC_TAG_STAT_VALUE_TYPE children.
   * @param {Object[]} tags - Array of raw EC tags
   * @returns {Object} Nested object tree keyed by tag name strings
   */
  buildTagTree(tags) {
    const obj = {};
    
    for (const tag of tags) {
      // Skip EC_TAG_STATTREE_NODEID - not needed in output
      if (tag.tagIdStr === 'EC_TAG_STATTREE_NODEID') continue;
      
      // Check if this tag has a value type specified in children
      let valueType = null;
      let formattedValue = tag.humanValue;
      
      if (tag.children && tag.children.length > 0) {
        const valueTypeTag = tag.children.find(child => child.tagIdStr === 'EC_TAG_STAT_VALUE_TYPE');
        if (valueTypeTag) {
          valueType = valueTypeTag.humanValue;
          formattedValue = this.formatValue(tag.humanValue, valueType);
        }
      }
      
      // Recursively build children (excluding EC_TAG_STAT_VALUE_TYPE and EC_TAG_STATTREE_NODEID)
      const childrenObj = tag.children && tag.children.length > 0 
        ? this.buildTagTree(tag.children.filter(child => 
            child.tagIdStr !== 'EC_TAG_STAT_VALUE_TYPE' && 
            child.tagIdStr !== 'EC_TAG_STATTREE_NODEID'
          ))
        : null;
      
      // Determine the node structure based on what we have
      let node;
      if (childrenObj && Object.keys(childrenObj).length > 0) {
        // Has children - create object with value (if meaningful) and spread children
        if (formattedValue !== undefined && formattedValue !== null && formattedValue !== '') {
          node = { _value: formattedValue, ...childrenObj };
        } else {
          node = childrenObj;
        }
      } else {
        // No children - just use the formatted value directly
        node = formattedValue;
      }

      // Handle duplicate keys by converting to array
      if (obj.hasOwnProperty(tag.tagIdStr)) {
        if (!Array.isArray(obj[tag.tagIdStr])) {
          obj[tag.tagIdStr] = [obj[tag.tagIdStr]];
        }
        obj[tag.tagIdStr].push(node);
      } else {
        obj[tag.tagIdStr] = node;
      }
    }

    return obj;
  }

  // ==========================================================================
  // PREFERENCES
  // ==========================================================================

  /**
   * Get connection preferences from aMule.
   * All speed/capacity values are in kB/s.
   * @returns {Promise<Object>} Connection preferences:
   *   { slotAllocation (kB/s per upload slot), maxDownload (kB/s, 0=unlimited), maxUpload (kB/s, 0=unlimited),
   *     dlCapacity (kB/s, graph scale), ulCapacity (kB/s, graph scale),
   *     tcpPort, udpPort, udpDisabled, maxConnections, autoConnect, ed2kEnabled, kadEnabled }
   */
  /**
   * Read the core's directory preferences.
   *
   * Not cached: aMule applies these live — a prefs write calls
   * EnableDirectoryWatcher — so the value can change under a long-lived
   * connection. Re-read when it matters.
   *
   * @returns {Promise<{ incoming: string|undefined, temp: string|undefined, shared: string[], shareHidden: boolean, autoRescan: boolean, followSymlinks: boolean, excludePatterns: string|undefined, excludeRegex: boolean }>}
   *   `autoRescan` says the core watches its shared directories itself, so a
   *   caller need not issue EC_OP_SHAREDFILES_RELOAD after its own changes.
   *   False when the user turned it off and equally on a core too old to send
   *   the tag — 2.3.3's block ends at EC_TAG_DIRECTORIES_SHARE_HIDDEN and never
   *   reused 0x1A05, so absence is unambiguous.
   */
  async getDirectoryPreferences() {
    if (DEBUG) console.log("[DEBUG] Requesting directory preferences...");

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_SELECT_PREFS,
        EC_TAG_TYPES.EC_TAGTYPE_UINT32,
        EC_PREFS.EC_PREFS_DIRECTORIES
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_PREFERENCES, reqTags);

    if (DEBUG) console.log("[DEBUG] Directory preferences response:", JSON.stringify(response, null, 2));

    return this._parseDirectoryPreferences(response.tags);
  }

  async getConnectionPreferences() {
    if (DEBUG) console.log("[DEBUG] Requesting connection preferences...");

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_SELECT_PREFS,
        EC_TAG_TYPES.EC_TAGTYPE_UINT32,
        EC_PREFS.EC_PREFS_CONNECTIONS
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_PREFERENCES, reqTags);

    if (DEBUG) console.log("[DEBUG] Connection preferences response:", JSON.stringify(response, null, 2));

    return this._parseConnectionPreferences(response.tags);
  }

  /**
   * Set connection preferences on aMule.
   * Only the fields provided will be updated — omitted fields remain unchanged.
   * All speed/capacity values are in kB/s.
   * @param {Object} prefs - Preferences to set (all optional):
   *   { slotAllocation (kB/s per upload slot), maxDownload (kB/s, 0=unlimited),
   *     maxUpload (kB/s, 0=unlimited), dlCapacity (kB/s, graph scale), ulCapacity (kB/s, graph scale),
   *     maxConnections }
   * @returns {Promise<boolean>} True if preferences were set successfully
   */
  async setConnectionPreferences(prefs) {
    if (DEBUG) console.log("[DEBUG] Setting connection preferences:", prefs);

    const children = [];

    if (prefs.slotAllocation !== undefined) {
      children.push({
        tagId: EC_TAGS.EC_TAG_CONN_SLOT_ALLOCATION,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT32,
        value: prefs.slotAllocation
      });
    }
    if (prefs.maxDownload !== undefined) {
      children.push({
        tagId: EC_TAGS.EC_TAG_CONN_MAX_DL,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT32,
        value: prefs.maxDownload
      });
    }
    if (prefs.maxUpload !== undefined) {
      children.push({
        tagId: EC_TAGS.EC_TAG_CONN_MAX_UL,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT32,
        value: prefs.maxUpload
      });
    }
    if (prefs.dlCapacity !== undefined) {
      children.push({
        tagId: EC_TAGS.EC_TAG_CONN_DL_CAP,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT32,
        value: prefs.dlCapacity
      });
    }
    if (prefs.ulCapacity !== undefined) {
      children.push({
        tagId: EC_TAGS.EC_TAG_CONN_UL_CAP,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT32,
        value: prefs.ulCapacity
      });
    }
    if (prefs.maxConnections !== undefined) {
      children.push({
        tagId: EC_TAGS.EC_TAG_CONN_MAX_CONN,
        tagType: EC_TAG_TYPES.EC_TAGTYPE_UINT16,
        value: prefs.maxConnections
      });
    }

    if (children.length === 0) {
      throw new Error('No preferences provided');
    }

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_PREFS_CONNECTIONS,
        EC_TAG_TYPES.EC_TAGTYPE_CUSTOM,
        undefined,
        children
      )
    ];

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SET_PREFERENCES, reqTags);
    return this._isSuccess(response);
  }

  /**
   * Parse connection preferences from EC response tags.
   * @param {Object[]} tags - Response tags
   * @returns {Object} Parsed preferences
   * @private
   */
  _parseDirectoryPreferences(tags) {
    const result = { shared: [] };
    const prefsTag = tags.find(t => t.tagId === EC_TAGS.EC_TAG_PREFS_DIRECTORIES);
    if (!prefsTag || !prefsTag.children) return result;

    // Value tags — read humanValue
    const valueFields = {
      [EC_TAGS.EC_TAG_DIRECTORIES_INCOMING]: 'incoming',
      [EC_TAGS.EC_TAG_DIRECTORIES_TEMP]: 'temp',
      [EC_TAGS.EC_TAG_DIRECTORIES_EXCLUDE_PATTERNS]: 'excludePatterns'
    };

    // Presence tags — aMule adds these only when true and omits them when
    // false, so they arrive as zero-length CECEmptyTags with no value at all.
    const presenceFields = {
      [EC_TAGS.EC_TAG_DIRECTORIES_SHARE_HIDDEN]: 'shareHidden',
      [EC_TAGS.EC_TAG_DIRECTORIES_AUTO_RESCAN]: 'autoRescan',
      [EC_TAGS.EC_TAG_DIRECTORIES_FOLLOW_SYMLINKS]: 'followSymlinks'
    };

    for (const field of Object.values(presenceFields)) {
      result[field] = false;
    }
    // Not a presence tag despite being a boolean: aMule always sends it, with
    // the value in it.
    result.excludeRegex = false;

    for (const child of prefsTag.children) {
      const valueField = valueFields[child.tagId];
      if (valueField) {
        result[valueField] = child.humanValue;
        continue;
      }
      const presenceField = presenceFields[child.tagId];
      if (presenceField) {
        result[presenceField] = true;
        continue;
      }
      if (child.tagId === EC_TAGS.EC_TAG_DIRECTORIES_EXCLUDE_REGEX) {
        result.excludeRegex = Boolean(child.humanValue);
        continue;
      }
      if (child.tagId === EC_TAGS.EC_TAG_DIRECTORIES_SHARED) {
        // The tag's own value is the count; the paths are EC_TAG_STRING children.
        result.shared = (child.children || [])
          .filter(c => c.tagId === EC_TAGS.EC_TAG_STRING)
          .map(c => c.humanValue);
      }
    }

    return result;
  }

  _parseConnectionPreferences(tags) {
    const result = {};
    const prefsTag = tags.find(t => t.tagId === EC_TAGS.EC_TAG_PREFS_CONNECTIONS);
    if (!prefsTag || !prefsTag.children) return result;

    // Value tags — read humanValue
    const valueFields = {
      [EC_TAGS.EC_TAG_CONN_SLOT_ALLOCATION]: 'slotAllocation',
      [EC_TAGS.EC_TAG_CONN_MAX_DL]: 'maxDownload',
      [EC_TAGS.EC_TAG_CONN_MAX_UL]: 'maxUpload',
      [EC_TAGS.EC_TAG_CONN_DL_CAP]: 'dlCapacity',
      [EC_TAGS.EC_TAG_CONN_UL_CAP]: 'ulCapacity',
      [EC_TAGS.EC_TAG_CONN_TCP_PORT]: 'tcpPort',
      [EC_TAGS.EC_TAG_CONN_UDP_PORT]: 'udpPort',
      [EC_TAGS.EC_TAG_CONN_MAX_CONN]: 'maxConnections'
    };

    // Presence tags — present = true, absent = false
    const presenceFields = {
      [EC_TAGS.EC_TAG_CONN_UDP_DISABLE]: 'udpDisabled',
      [EC_TAGS.EC_TAG_CONN_AUTOCONNECT]: 'autoConnect',
      [EC_TAGS.EC_TAG_NETWORK_ED2K]: 'ed2kEnabled',
      [EC_TAGS.EC_TAG_NETWORK_KADEMLIA]: 'kadEnabled'
    };

    // Initialize presence fields to false (absence = false)
    for (const field of Object.values(presenceFields)) {
      result[field] = false;
    }

    for (const child of prefsTag.children) {
      const valueField = valueFields[child.tagId];
      if (valueField) {
        result[valueField] = child.humanValue;
        continue;
      }
      const presenceField = presenceFields[child.tagId];
      if (presenceField) {
        result[presenceField] = true;
      }
    }

    return result;
  }
}

AmuleClient.CATEGORY_REASON = CATEGORY_REASON;
AmuleClient.SEARCH_DOWNLOAD_STATUS = SEARCH_DOWNLOAD_STATUS;
AmuleClient.SHAREDDIR_ERROR = SHAREDDIR_ERROR;

module.exports = AmuleClient;
