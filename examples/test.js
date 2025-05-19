const AmuleClient = require('./AmuleClient');

const DEBUG = true;
const amuleClient = new AmuleClient("127.0.0.1", 4712, "your_password");

(async function init() {
  try {
    await amuleClient.connect();

    if (DEBUG) console.log('Connected and authenticated successfully to aMule');

    console.log('Shared Files:', await amuleClient.getSharedFiles());
    console.log('Download Queue:', await amuleClient.getDownloadQueue());
    console.log('Search request:', await amuleClient.searchAndWaitResults('ubuntu', 'global', 'iso'));

  } catch (error) {
    console.error(`Could not connect to aMule:`, error);
  }
})();
