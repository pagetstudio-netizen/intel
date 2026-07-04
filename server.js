/**
 * INTEL Security Platform — Application Startup File (racine du projet)
 * Plesk > Node.js > Application Startup File = server.js
 * Application Root doit être la racine du projet (httpdocs/)
 */
process.env.NODE_ENV = process.env.NODE_ENV || 'production';

const path = require('path');
// S'assurer que process.cwd() est bien la racine du projet
process.chdir(path.resolve(__dirname));

// tsx est installé dans backend/node_modules — on l'enregistre depuis là
require('./backend/node_modules/tsx/cjs');
require('./backend/src/index.ts');
