/**
 * INTEL Security Platform — Point d'entrée Plesk/Production
 * Ce fichier est utilisé par Plesk comme "Application Startup File" Node.js
 */
process.env.NODE_ENV = process.env.NODE_ENV || 'production';

// Lance le backend TypeScript directement via tsx (pas besoin de compiler)
require('tsx/cjs');
require('./backend/src/index.ts');
