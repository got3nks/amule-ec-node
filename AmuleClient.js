"use strict";

const ECProtocol = require("./ECProtocol");
const {
  EC_OPCODES,
  EC_TAGS,
  EC_TAG_TYPES,
  EC_SEARCH_TYPE,
  EC_VALUE_TYPE,
  EC_PREFS
} = require("./ECDefs");

const DEBUG = false;

class AmuleClient {
  constructor(host, port, password) {
    this.session = new ECProtocol(host, port, password);
  }

  async connect() {
    await this.session.connect();
    await this.session.authenticate();
  }

  close() {
    this.session.close();
  }

  async getConnectionState() {
    if (DEBUG) console.log("[DEBUG] Requesting connection state...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_CONNSTATE, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this.buildTagTree(response.tags);
  }

  async getStats() {
    if (DEBUG) console.log("[DEBUG] Requesting stats...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_STAT_REQ, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this.buildTagTree(response.tags);
  }
  
  async getStatsTree() {
    if (DEBUG) console.log("[DEBUG] Requesting stats tree...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_STATSTREE, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this.buildTagTree(response.tags);
  }

  async getServerInfo() {
    if (DEBUG) console.log("[DEBUG] Requesting server info...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_SERVERINFO, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this.buildTagTree(response.tags);
  }

  async getLog() {
    if (DEBUG) console.log("[DEBUG] Requesting logs...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_LOG, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this.buildTagTree(response.tags);
  }

  async getDebugLog() {
    if (DEBUG) console.log("[DEBUG] Requesting debug logs...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_DEBUGLOG, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this.buildTagTree(response.tags);
  }

  async getServerList() {
    if (DEBUG) console.log("[DEBUG] Requesting server list...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_SERVER_LIST, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this.buildTagTree(response.tags);
  }

  async removeServer(ip, port) {
    if (DEBUG) console.log("[DEBUG] Removing server...");

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_SERVER,
        EC_TAG_TYPES.EC_TAGTYPE_IPV4,
        {ip, port}
      )
    ];
    
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SERVER_REMOVE, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return response.opcode==1;
  }

  async connectServer(ip, port) {
    if (DEBUG) console.log("[DEBUG] Connecting to server...");

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_SERVER,
        EC_TAG_TYPES.EC_TAGTYPE_IPV4,
        {ip, port}
      )
    ];
    
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SERVER_CONNECT, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return response.opcode==1;
  }

  async disconnectServer(ip, port) {
    if (DEBUG) console.log("[DEBUG] Disconnecting from server...");

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_SERVER,
        EC_TAG_TYPES.EC_TAGTYPE_IPV4,
        {ip, port}
      )
    ];
    
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SERVER_DISCONNECT, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return response.opcode==1;
  }

  async getDownloadingQueue() {
    if (DEBUG) console.log("[DEBUG] Requesting download queue...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_DLOAD_QUEUE, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this.buildTagTree(response.tags);
  }

  async getUploadingQueue() {
    if (DEBUG) console.log("[DEBUG] Requesting upload queue...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_ULOAD_QUEUE, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return this.buildTagTree(response.tags);
  }

  async getSharedFiles() {
    if (DEBUG) console.log("[DEBUG] Requesting shared files...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_SHARED_FILES, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    // Parse response data into structured JS object
    const sharedFiles = response.tags.map(tag => ({
      fileName: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_NAME)?.humanValue,
      fileHash: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_HASH)?.humanValue,
      fileSize: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_SIZE_FULL)?.humanValue,
      transferred: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_KNOWNFILE_XFERRED)?.humanValue,
      transferredTotal: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_KNOWNFILE_XFERRED_ALL)?.humanValue,
      reqCount: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_KNOWNFILE_REQ_COUNT)?.humanValue,
      reqCountTotal: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_KNOWNFILE_REQ_COUNT_ALL)?.humanValue,
      acceptedCount: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_KNOWNFILE_ACCEPT_COUNT)?.humanValue,
      acceptedCountTotal: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_KNOWNFILE_ACCEPT_COUNT_ALL)?.humanValue,
      priority: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_KNOWNFILE_PRIO)?.humanValue,
    }));

    return sharedFiles;
  }

  async getDownloadQueue() {
    if (DEBUG) console.log("[DEBUG] Requesting downloaded files...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_GET_DLOAD_QUEUE, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    // Parse response data into structured JS object
    const downloadQueue = response.tags.map(tag => ({
      fileName: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_NAME)?.humanValue,
      fileHash: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_HASH)?.humanValue,
      fileSize: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_SIZE_FULL)?.humanValue,
      fileSizeDownloaded: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_SIZE_DONE)?.humanValue,
      progress: ((tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_SIZE_DONE)?.humanValue / tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_SIZE_FULL)?.humanValue) * 100).toFixed(2),
      sourceCount: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_SOURCE_COUNT)?.humanValue,
      speed: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_SPEED)?.humanValue,
      priority: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_PRIO)?.humanValue,
      category: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_CAT)?.humanValue || 0,
      lastSeenComplete: this.formatUnixTimestamp(tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_LAST_SEEN_COMP)?.humanValue),
    }));

    return downloadQueue;
  }

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

  async _getSearchRequestStatus() {
    if (DEBUG) console.log("[DEBUG] Requesting search request status...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SEARCH_PROGRESS, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return response.tags;
  }

  async getSearchResults() {
    if (DEBUG) console.log("[DEBUG] Requesting search request status...");
    
    // Send request
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_SEARCH_RESULTS, []);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    // Fetch results and parse them
    let results =  response.tags.map(tag => ({
      fileName: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_NAME)?.humanValue,
      fileHash: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_HASH)?.humanValue,
      fileSize: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_SIZE_FULL)?.humanValue,
      sourceCount: tag.children.find(child => child.tagId === EC_TAGS.EC_TAG_PARTFILE_SOURCE_COUNT)?.humanValue,
    }));

    results.sort((a, b) => (b.sourceCount || 0) - (a.sourceCount || 0));

    return { resultsLength: results.length, results: results };
  }

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

   async cancelDownload(fileHash) {
    if (DEBUG) console.log("[DEBUG] Requesting delete file ",fileHash,"...");

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_PARTFILE,
        EC_TAG_TYPES.EC_TAGTYPE_HASH16,
        fileHash
      )
    ];
    
    const response = await this.session.sendPacket(EC_OPCODES.EC_OP_PARTFILE_DELETE, reqTags);

    if (DEBUG) console.log("[DEBUG] Received response:", response);

    return response.opcode==1;
  }

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

    return response.opcode==1;
  }

  // Category Management Methods

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
    const success = categoryId !== null || response.opcode === EC_OPCODES.EC_OP_NOOP || response.opcode === 0x01;

    if (DEBUG) console.log("[DEBUG] Category creation success:", success, "categoryId:", categoryId, "opcode:", response.opcode);

    return {
      success: success,
      categoryId: categoryId
    };
  }

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

    return response.opcode === EC_OPCODES.EC_OP_NOOP || response.opcode === 0x01;
  }

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

    return response.opcode === EC_OPCODES.EC_OP_NOOP || response.opcode === 0x01;
  }

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

    return response.opcode === EC_OPCODES.EC_OP_NOOP || response.opcode === 0x01;
  }
 
  /*
      Helper functions
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

  parseCategoryIdFromResponse(response) {
    // aMule returns the new category ID in the response
    // Look for EC_TAG_CATEGORY tag with the new ID
    const categoryTag = response.tags?.find(t => t.tagId === EC_TAGS.EC_TAG_CATEGORY);
    return categoryTag?.humanValue || categoryTag?.value || null;
  }

  formatUnixTimestamp(unixTimestamp) {
    const date = new Date(unixTimestamp * 1000); // Convert seconds to milliseconds

    const dd = String(date.getDate()).padStart(2, '0');
    const mm = String(date.getMonth() + 1).padStart(2, '0'); // Months are 0-indexed
    const yyyy = date.getFullYear();

    const minutes = String(date.getMinutes()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');

    return `${dd}-${mm}-${yyyy} ${minutes}:${hours}:${seconds}`;
  }

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
