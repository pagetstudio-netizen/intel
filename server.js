/**
 * INTEL Security Platform — Application Startup File (racine du projet)
 * Plesk > Node.js > Application Startup File = server.js
 * Application Root doit être la racine du projet (httpdocs/)
 */
process.env.NODE_ENV = process.env.NODE_ENV || 'production';

const path = require('path');
// S'assurer que process.cwd() est bien la racine du projet
process.chdir(path.resolve(__dirname));

require('tsx/cjs');
require('./backend/src/index.ts');
