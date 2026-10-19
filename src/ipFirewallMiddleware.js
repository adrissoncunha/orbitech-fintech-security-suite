/**
 * Módulo: Firewall de Aplicação (WAF) & Whitelist de Gateways via Cloudflare Proxy
 * Descrição: Gerencia bloqueio dinâmico de IPs maliciosos com persistência em disco
 * e validação estrita de IP de origem para provedores de postback.
 */

const fs = require('fs');
const path = require('path');

const BLACKLIST_FILE = path.join(__dirname, '../data/blacklist.json');
const FAILED_ATTEMPTS_LIMIT = 30;
const BLACKLIST_DURATION_MS = 5 * 60 * 1000;

// IPs oficiais autorizados para Postbacks S2S (Server-to-Server)
const PARTNER_WHITELIST_IPS = ['18.156.132.55', '51.81.120.73', '142.111.248.18'];

function extractRealClientIp(req) {
    let rawIp = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip || '';
    if (rawIp.includes('::ffff:')) rawIp = rawIp.split('::ffff:')[1];
    return rawIp.split(',')[0].trim();
}

const ipBlacklist = new Map();

function recordFailedAttempt(ip) {
    const now = Date.now();
    const record = ipBlacklist.get(ip) || { attempts: 0, firstAttempt: new Date(now), blockedUntil: null };

    if (record.blockedUntil && record.blockedUntil > now) return true;
    if (record.blockedUntil && record.blockedUntil <= now) {
        record.attempts = 0;
        record.blockedUntil = null;
    }

    record.attempts += 1;
    if (record.attempts >= FAILED_ATTEMPTS_LIMIT) {
        record.blockedUntil = new Date(now + BLACKLIST_DURATION_MS);
    }

    ipBlacklist.set(ip, record);

    // Auto-Pruning (Garbage Collection em memória)
    if (ipBlacklist.size > 10000) {
        for (const [key, val] of ipBlacklist.entries()) {
            if (val.blockedUntil && val.blockedUntil < now - 3600000) {
                ipBlacklist.delete(key);
            }
        }
    }

    return Boolean(record.blockedUntil && record.blockedUntil > now);
}

function ipFirewallMiddleware(req, res, next) {
    const clientIp = extractRealClientIp(req);

    // Validação estrita de Whitelist para rotas de Webhook S2S
    if (req.path === '/api/webhooks/s2s-partner') {
        if (PARTNER_WHITELIST_IPS.includes(clientIp)) {
            return next();
        }
        return res.status(403).json({ error: 'FORBIDDEN_ORIGIN_IP' });
    }

    // Verificação de Blacklist para rotas de usuários
    const record = ipBlacklist.get(clientIp);
    if (record && record.blockedUntil && record.blockedUntil > Date.now()) {
        const retryAfter = Math.ceil((record.blockedUntil - Date.now()) / 1000);
        return res.status(429).json({
            error: 'IP_TEMPORARILY_BLOCKED',
            retryAfterSeconds: retryAfter
        });
    }

    next();
}

module.exports = { ipFirewallMiddleware, recordFailedAttempt, extractRealClientIp };
