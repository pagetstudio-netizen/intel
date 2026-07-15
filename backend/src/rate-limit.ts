import rateLimit from 'express-rate-limit';

// Les scans/fuzz/load-test déclenchent des requêtes réseau sortantes et le binaire
// Rust — un débit élevé permet un abus en DoS ou un détournement en proxy d'attaque.
export const scanLimiter = rateLimit({
  windowMs: 60_000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de requêtes — réessayez dans une minute.' },
});

// Limite plus large pour les endpoints de lecture/écriture classiques (mandats, emails).
export const mutationLimiter = rateLimit({
  windowMs: 60_000,
  limit: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de requêtes — réessayez dans une minute.' },
});
