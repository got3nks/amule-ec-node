"use strict";

const ECProtocol = require("./ECProtocol");
const {
  EC_OPCODES,
  EC_TAGS,
  EC_TAG_TYPES,
  EC_SEARCH_TYPE,
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

  async downloadSearchResult(fileHash) {
    if (DEBUG) console.log("[DEBUG] Requesting download ",filehHsh," from search result...");

    const reqTags = [
      this.session.createTag(
        EC_TAGS.EC_TAG_PARTFILE,
        EC_TAG_TYPES.EC_TAGTYPE_HASH16,
        fileHash
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
}

module.exports = AmuleClient;
