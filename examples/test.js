const AmuleClient = require('./../AmuleClient');

const AMULE_HOST = process.env.AMULE_HOST || '127.0.0.1';
const AMULE_PORT = process.env.AMULE_PORT || 4712;
const AMULE_PASSWORD = process.env.AMULE_PASSWORD || 'admin';
const DEBUG = true;

const amuleClient = new AmuleClient(AMULE_HOST, AMULE_PORT, AMULE_PASSWORD);

(async function init() {
  try {
    await amuleClient.connect();
    if (DEBUG) console.log('Connected and authenticated successfully to aMule');
  } catch (error) {
    console.error('Could not connect to aMule:', error);
    process.exit(1);
  }

  try {
    const stats = await amuleClient.getStats();
    console.dir(stats, { depth: null });
  } catch (error) {
    console.error('Error executing aMule commands:', error);
  }

  try {
    const sharedFiles = await amuleClient.getSharedFiles();
    const names = sharedFiles.map(file => file.fileName).sort();
    console.dir(names, { depth: null });
  } catch (error) {
    console.error('Error executing aMule commands:', error);
  }

  try {
    amuleClient.close();
    console.log('Disconnected from aMule');
  } catch (err) {
    console.error('Error disconnecting:', err);
  }
})();
