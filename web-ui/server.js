/**
 * INTEL — Application Startup File pour Plesk
 * Utilisé quand Application Root est configuré sur "web-ui/" dans Plesk
 * Ce fichier remonte à la racine du projet et lance le backend
 */
process.env.NODE_ENV = process.env.NODE_ENV || 'production';

const path = require('path');
// Remonter d'un niveau : web-ui/ → racine du projet
const projectRoot = path.resolve(__dirname, '..');
process.chdir(projectRoot);

require('tsx/cjs');
require(path.join(projectRoot, 'backend', 'src', 'index.ts'));
