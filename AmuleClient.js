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

class AmuleClient {
  /**
   * @param {string} host - aMule EC hostname or IP address
   * @param {number} port - aMule EC port (default 4712)
   * @param {string} password - EC access password
   * @param {Object} [options] - Additional options passed to ECProtocol
   */
  constructor(host, port, password, options = {}) {
    this.session = new ECProtocol(host, port, password, options);
  }

  /**
   * Connect to aMule and authenticate.
   */
  async connect() {
    await this.session.connect();
    await this.session.authenticate();
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
   * Send a command targeting a server by IP and port.
   * @param {number} opcode - EC opcode to send
   * @param {string} ip - Server IP address
   * @param {number} port - Server port
   * @returns {boolean} True if the command succeeded
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
   * @returns {boolean} True if the command succeeded
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
   * @returns {Object} Parsed tag tree
   * @private
   */
  async _requestTagTree(opcode) {
    const response = await this.session.sendPacket(opcode, []);
    if (DEBUG) console.log("[DEBUG] Received response:", response);
    return this.buildTagTree(response.tags);
  }

  /**
   * Get the current connection state (ed2k server, Kad network).
   * @returns {Object} Tag tree with connection state fields
   */
  async getConnectionState() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_CONNSTATE);
  }

  /**
   * Get aMule statistics (upload/download speed, shared file count, etc.).
   * @returns {Object} Tag tree with stats fields
   */
  async getStats() {
    return this._requestTagTree(EC_OPCODES.EC_OP_STAT_REQ);
  }

  /**
   * Get the full statistics tree (hierarchical stats with node IDs).
   * @returns {Object} Tag tree with nested stats
   */
  async getStatsTree() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_STATSTREE);
  }

  /**
   * Get ed2k server info (message of the day, etc.).
   * @returns {Object} Tag tree with server info
   */
  async getServerInfo() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_SERVERINFO);
  }

  /**
   * Get aMule log messages.
   * @returns {Object} Tag tree with log entries
   */
  async getLog() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_LOG);
  }

  /**
   * Get aMule debug log messages.
   * @returns {Object} Tag tree with debug log entries
   */
  async getDebugLog() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_DEBUGLOG);
  }

  /**
   * Get the list of ed2k servers.
   * @returns {Object} Tag tree with server entries
   */
  async getServerList() {
    return this._requestTagTree(EC_OPCODES.EC_OP_GET_SERVER_LIST);
  }

  /**
   * Remove an ed2k server from the server list.
   * @param {string} ip - Server IP address
   * @param {number} port - Server port
   * @returns {boolean} True if the server was removed successfully
   */
  async removeServer(ip, port) {
    return this._sendServerCommand(EC_OPCODES.EC_OP_SERVER_REMOVE, ip, port);
  }

  /**
   * Connect to an ed2k server.
   * @param {string} ip - Server IP address
   * @param {number} port - Server port
   * @returns {boolean} True if connection was initiated successfully
   */
  async connectServer(ip, port) {
    return this._sendServerCommand(EC_OPCODES.EC_OP_SERVER_CONNECT, ip, port);
  }

  /**
   * Disconnect from an ed2k server.
   * @param {string} ip - Server IP address
   * @param {number} port - Server port
   * @returns {boolean} True if disconnection was successful
   */
  async disconnectServer(ip, port) {
    return this._sendServerCommand(EC_OPCODES.EC_OP_SERVER_DISCONNECT, ip, port);
  }

  /**
   * Get the upload queue (clients waiting to download from us).
   * @returns {Object} Tag tree with upload queue entries
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
   * @returns {boolean} True if the reload was initiated successfully
   */
  async refreshSharedFiles() {
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SHAREDFILES_RELOAD, []);
    if (DEBUG) console.log("[DEBUG] Received response:", response);
    return this._isSuccess(response);
  }

  /**
   * Get the full download queue (non-incremental).
   * Unlike getUpdate(), this always returns the complete list.
   * @returns {Object[]} Array of download objects with parsed fields
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
    for (const ecid of this._updateState.downloads.keys()) {
      if (!seenDownloads.has(ecid)) {
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
    // Remove shared files no longer present (unshared)
    for (const ecid of this._updateState.sharedFiles.keys()) {
      if (!seenSharedFiles.has(ecid)) {
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
      for (const ecid of this._updateState.clients.keys()) {
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
   * Start a search on the specified network.
   * @param {string} query - Search query string
   * @param {number} network - Network type (EC_SEARCH_TYPE value)
   * @param {string|null} [extension] - Optional file extension filter
   * @returns {Object[]} Raw response tags
   * @private
   */
  async _search(query, network, extension=null) {
    if (DEBUG) console.log("[DEBUG] Requesting search...");

    // Make sure network flag is valid
    if (!Object.values(EC_SEARCH_TYPE).includes(network)) throw new Error(`Invalid network type: ${network}`);
    
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
        network,
        children
      )
    ];
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SEARCH_START, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return response.tags;
  }

  /**
   * Get the progress status of an ongoing search.
   * @returns {Object[]} Raw response tags with search progress
   * @private
   */
  async _getSearchRequestStatus() {
    if (DEBUG) console.log("[DEBUG] Requesting search request status...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SEARCH_PROGRESS, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return response.tags;
  }

  /**
   * Get the results of a completed search.
   * @returns {{ resultsLength: number, results: Object[] }} Search results sorted by source count
   */
  async getSearchResults() {
    if (DEBUG) console.log("[DEBUG] Requesting search results...");

    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SEARCH_RESULTS, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    const results = response.tags.map(tag => this._parseDownloadFields(tag));
    results.sort((a, b) => (b.sourceCount || 0) - (a.sourceCount || 0));

    return { resultsLength: results.length, results };
  }

  /**
   * Start a search and poll until results are ready (up to 120s timeout).
   * @param {string} query - Search query string
   * @param {string|number} network - Network type: 'global', 'local', 'kad', or EC_SEARCH_TYPE value
   * @param {string} [extension] - Optional file extension filter
   * @returns {{ resultsLength: number, results: Object[] }} Search results sorted by source count
   */
  async searchAndWaitResults(query, network, extension) {
    const timeoutMs = 120000;
    const intervalMs = 1000;
    const startTime = Date.now();

    if (!Object.values(EC_SEARCH_TYPE).includes(network)) {
      switch(network) {
        case 'global':
          network=EC_SEARCH_TYPE.EC_SEARCH_GLOBAL;
          break;
        case 'local':
          network=EC_SEARCH_TYPE.EC_SEARCH_LOCAL;
          break;
        case 'kad':
          network=EC_SEARCH_TYPE.EC_SEARCH_KAD;
          break;
      }
    }

    // Start the search
    await this._search(query, network, extension);

    if (DEBUG) console.log("[DEBUG] Waiting for search to complete...");
    await new Promise(resolve => setTimeout(resolve, 5000)); // for global/local searches, let's give amule some time for the progress to re-initialize

    while (true) {
      const elapsed = Date.now() - startTime;
      if (elapsed >= timeoutMs) throw new Error("Search timed out");

      const statusTags = await this._getSearchRequestStatus();
      const statusTag = statusTags.find(tag => tag.tagId === EC_TAGS.EC_TAG_SEARCH_STATUS);
      const statusValue = statusTag?.humanValue;

      if (
        (network == EC_SEARCH_TYPE.EC_SEARCH_KAD &&  (statusValue === 0xFFFF || statusValue === 0xFFFE)) || 
        (network == EC_SEARCH_TYPE.EC_SEARCH_GLOBAL && (statusValue == 100 || statusValue == 0)) || 
        (network == EC_SEARCH_TYPE.EC_SEARCH_LOCAL && elapsed >= 10000) // we get no progress for local searches, but they should be fast
      ) {
        if (DEBUG) console.log("[DEBUG] Search completed.");
        break;
      }

      if (DEBUG) console.log(`[DEBUG] Search ${network} progress: ${statusValue}`);
      await new Promise(resolve => setTimeout(resolve, intervalMs));
    }

    return this.getSearchResults?.() ?? null;
  }

  /**
   * Download a file from search results.
   * @param {string} fileHash - MD4 hash of the file to download
   * @param {number} [categoryId=0] - Category ID to assign (0 = default)
   * @returns {boolean} True if the download was started successfully
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
   * @returns {boolean} True if the download was cancelled successfully
   */
  async cancelDownload(fileHash) {
    return this._sendFileCommand(EC_OPCODES.EC_OP_PARTFILE_DELETE, fileHash);
  }

  /**
   * Add a download via ed2k:// link.
   * @param {string} link - ed2k:// link
   * @param {number} [categoryId=0] - Category ID to assign (0 = default)
   * @returns {boolean} True if the link was added successfully
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
   * @returns {boolean} True if the download was paused successfully
   */
  async pauseDownload(fileHash) {
    return this._sendFileCommand(EC_OPCODES.EC_OP_PARTFILE_PAUSE, fileHash);
  }

  /**
   * Resume a paused download.
   * @param {string} fileHash - MD4 hash of the file to resume
   * @returns {boolean} True if the download was resumed successfully
   */
  async resumeDownload(fileHash) {
    return this._sendFileCommand(EC_OPCODES.EC_OP_PARTFILE_RESUME, fileHash);
  }

  /**
   * Get all aMule categories.
   * @returns {Object[]} Array of category objects with { id, title, path, comment, color, priority }
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
   * Create a new category in aMule.
   * @param {string} title - Category name
   * @param {string} [path=''] - Download path for this category
   * @param {string} [comment=''] - Category comment
   * @param {number} [color=0] - Category color in RGB format (0xRRGGBB)
   * @param {number} [priority=0] - Download priority for this category
   * @returns {{ success: boolean, categoryId: number|null }} Result with the new category ID
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

    // Parse the new category ID from response
    const categoryId = this.parseCategoryIdFromResponse(response);

    // Success if we got a valid category ID back (aMule created it)
    // OR if the opcode indicates success
    const success = categoryId !== null || this._isSuccess(response);

    if (DEBUG) console.log("[DEBUG] Category creation success:", success, "categoryId:", categoryId, "opcode:", response.opcode);

    return {
      success: success,
      categoryId: categoryId
    };
  }

  /**
   * Update an existing category in aMule.
   * @param {number} categoryId - Category ID to update
   * @param {string} title - Category name
   * @param {string} path - Download path
   * @param {string} comment - Category comment
   * @param {number} color - Category color in RGB format (0xRRGGBB)
   * @param {number} priority - Download priority
   * @returns {boolean} True if the update was successful
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

    return this._isSuccess(response);
  }

  /**
   * Delete a category from aMule.
   * @param {number} categoryId - Category ID to delete
   * @returns {boolean} True if the deletion was successful
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

    return this._isSuccess(response);
  }

  /**
   * Assign a download to a category.
   * @param {string} fileHash - MD4 hash of the file
   * @param {number} categoryId - Category ID to assign
   * @returns {boolean} True if the category was set successfully
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
   * @returns {{ success: boolean, error?: string }} Result with optional error message
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
        case EC_TAGS.EC_TAG_PARTFILE_NAME:                    result.fileName = val; break;
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
      // aMule's RLE_Data XOR-diffs against the previous interleaved buffer.
      // When the gap count changes, the buffer size changes too. aMule
      // zero-extends (grow) or truncates (shrink) the old buffer before XOR,
      // so the diff is always the new size. We XOR overlapping bytes with
      // prev and treat the rest as raw (XOR with implied zeros = identity).
      const state = this._ecBufferState.get(ecid) || {};
      const prev = state[out];
      let current;
      let xorApplied = false;
      if (prev) {
        current = Buffer.from(decoded); // copy decoded
        const overlapLen = Math.min(decoded.length, prev.length);
        for (let i = 0; i < overlapLen; i++) {
          current[i] = decoded[i] ^ prev[i];
        }
        // Bytes beyond overlapLen stay as decoded[i] (XOR with zero = identity)
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

      if (DEBUG && uint64 && fields[out].length > 0) {
        console.log(`[EC-RECONSTRUCT]   → ${fields[out].length} pairs, first 3:`, fields[out].slice(0, 3));
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
   * @returns {{fileName: string, fileHash: string, fileSize: number, transferred: number, transferredTotal: number, reqCount: number, reqCountTotal: number, acceptedCount: number, acceptedCountTotal: number, priority: number, path: string, completeSources: number, onQueue: number, ed2kLink: string}[]} Parsed shared file fields
   * @private
   */
  _parseSharedFileFields(tag) {
    const result = {};
    if (!tag.children) return result;

    for (const sub of tag.children) {
      const val = sub.humanValue;
      switch (sub.tagId) {
        case EC_TAGS.EC_TAG_PARTFILE_NAME:               result.fileName = val; break;
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
        case EC_TAGS.EC_TAG_PARTFILE_NAME:          result.transferFileName = val; break;
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
    return categoryTag?.humanValue || categoryTag?.value || null;
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
}

module.exports = AmuleClient;
