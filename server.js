/**
 * ShadowXLab · Splunk Enterprise Security Standalone Ingestion Engine & Server
 * ----------------------------------------------------------------------------
 * Runs on Node.js without requiring external dependencies (built-in http, fs, path, dgram, net).
 * Ports:
 *   - HTTP Web & HEC: 8000 (http://localhost:8000/splunk.html)
 *   - Syslog UDP Listener: 1514 (udp://localhost:1514)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const dgram = require('dgram');
const net = require('net');

const HTTP_PORT = process.env.PORT || 8000;
const SYSLOG_PORT = 1514;
const HEC_TOKEN = 'sxl-splunk-hec-token-2026';

// State Stores (Clean On-Premises State - Zero Preloaded Data)
let sseClients = [];
let ingestedLogs = [];
let registeredAssets = [];
let liveFindings = [];

// Broadcast event to connected SSE clients
function broadcastSSE(type, data) {
  const msg = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(res => {
    try { res.write(msg); } catch (e) {}
  });
}

// Risk-Based Alerting Parser
function processIncomingLog(rawLog, host, sourcetype) {
  const timeStr = new Date().toLocaleTimeString();
  const logEntry = {
    id: 'L-' + (ingestedLogs.length + 1),
    timestamp: new Date().toISOString(),
    time: timeStr,
    host: host || 'unknown-host',
    sourcetype: sourcetype || 'generic:syslog',
    raw: rawLog
  };

  ingestedLogs.unshift(logEntry);
  if (ingestedLogs.length > 500) ingestedLogs.pop();

  // Threat Detection Rules
  // Threat & Telemetry Detection Rules
  const lower = rawLog.toLowerCase();
  let finding = null;

  if (lower.includes('failed password') || lower.includes('4625') || lower.includes('authentication failure')) {
    finding = {
      id: 'ES-' + String(1000 + liveFindings.length + 1).slice(-4),
      title: 'Real-time: Excessive Failed Logins from ' + (host || 'Host'),
      type: 'finding',
      entity: host || '127.0.0.1',
      entityType: 'system',
      icon: 'fa-desktop',
      risk: 85,
      fin: 1,
      intCount: 1,
      time: 'Just now',
      disposition: 'Undetermined',
      owner: 'Unassigned',
      urgency: 'high',
      status: 'new',
      mitre: 'T1110.001 - Password Guessing',
      domain: 'access',
      desc: `Real machine [${host}] reported failed authentication: ${rawLog.substring(0, 140)}`
    };
  } else if (lower.includes('powershell -enc') || lower.includes('encodedcommand') || lower.includes('cmd.exe /c')) {
    finding = {
      id: 'ES-' + String(1000 + liveFindings.length + 1).slice(-4),
      title: 'Real-time: Suspicious Encoded Script Execution on ' + (host || 'Host'),
      type: 'investigation',
      entity: host || '127.0.0.1',
      entityType: 'system',
      icon: 'fa-terminal',
      risk: 140,
      fin: 1,
      intCount: 1,
      time: 'Just now',
      disposition: 'Undetermined',
      owner: 'Unassigned',
      urgency: 'critical',
      status: 'new',
      mitre: 'T1059.001 - PowerShell Execution',
      domain: 'endpoint',
      desc: `EDR Telemetry on [${host}] flagged obfuscated execution: ${rawLog.substring(0, 140)}`
    };
  } else if (lower.includes('syn scan') || lower.includes('nmap') || lower.includes('port scan') || lower.includes('masscan')) {
    finding = {
      id: 'ES-' + String(1000 + liveFindings.length + 1).slice(-4),
      title: 'Real-time: Network Port Scan Reconnaissance from ' + (host || 'Host'),
      type: 'finding',
      entity: host || '127.0.0.1',
      entityType: 'system',
      icon: 'fa-network-wired',
      risk: 75,
      fin: 1,
      intCount: 1,
      time: 'Just now',
      disposition: 'Undetermined',
      owner: 'Unassigned',
      urgency: 'medium',
      status: 'new',
      mitre: 'T1046 - Network Service Scanning',
      domain: 'network',
      desc: `Port scanning activity detected originating from or targeting [${host}].`
    };
  } else if (lower.includes('agent online') || lower.includes('connected to splunk')) {
    finding = {
      id: 'ES-' + String(1000 + liveFindings.length + 1).slice(-4),
      title: 'Real-time Agent Online: Host [' + (host || 'Host') + '] Connected',
      type: 'finding',
      entity: host || '127.0.0.1',
      entityType: 'system',
      icon: 'fa-satellite-dish',
      risk: 30,
      fin: 1,
      intCount: 1,
      time: 'Just now',
      disposition: 'Undetermined',
      owner: 'Unassigned',
      urgency: 'low',
      status: 'new',
      mitre: 'T1082 - System Information Discovery',
      domain: 'endpoint',
      desc: `Live Splunk forwarder agent registered on ${host}. Streaming real-time system metrics.`
    };
  } else if (lower.includes('cpuload=')) {
    const cpuMatch = rawLog.match(/cpuload=(\d+)/i);
    const cpuVal = cpuMatch ? parseInt(cpuMatch[1], 10) : 0;
    if (cpuVal >= 70) {
      finding = {
        id: 'ES-' + String(1000 + liveFindings.length + 1).slice(-4),
        title: `High Compute Burst (${cpuVal}% CPU) on Host ${host || 'Host'}`,
        type: 'investigation',
        entity: host || '127.0.0.1',
        entityType: 'system',
        icon: 'fa-microchip',
        risk: 95,
        fin: 1,
        intCount: 1,
        time: 'Just now',
        disposition: 'Undetermined',
        owner: 'Unassigned',
        urgency: 'high',
        status: 'new',
        mitre: 'T1496 - Resource Hijacking',
        domain: 'endpoint',
        desc: `High compute usage detected on ${host}: ${rawLog}`
      };
    } else {
      const hasRecentFinding = liveFindings.some(f => f.entity === host && f.title.includes('Telemetry Stream'));
      if (!hasRecentFinding) {
        finding = {
          id: 'ES-' + String(1000 + liveFindings.length + 1).slice(-4),
          title: `Active Telemetry Stream from Real Host [${host}]`,
          type: 'finding',
          entity: host || '127.0.0.1',
          entityType: 'system',
          icon: 'fa-server',
          risk: 25,
          fin: 1,
          intCount: 1,
          time: 'Just now',
          disposition: 'Undetermined',
          owner: 'Unassigned',
          urgency: 'low',
          status: 'new',
          mitre: 'T1082 - System Discovery',
          domain: 'endpoint',
          desc: `Real system telemetry live stream: ${rawLog}`
        };
      }
    }
  } else if (lower.includes('denied') || lower.includes('drop') || lower.includes('block')) {
    finding = {
      id: 'ES-' + String(1000 + liveFindings.length + 1).slice(-4),
      title: 'Real-time: Firewall Policy Drop on ' + (host || 'Host'),
      type: 'finding',
      entity: host || '127.0.0.1',
      entityType: 'system',
      icon: 'fa-shield-alt',
      risk: 40,
      fin: 1,
      intCount: 1,
      time: 'Just now',
      disposition: 'Undetermined',
      owner: 'Unassigned',
      urgency: 'low',
      status: 'new',
      mitre: 'T1046 - Discovery',
      domain: 'network',
      desc: `Firewall dropped traffic: ${rawLog.substring(0, 140)}`
    };
  }

  if (finding) {
    liveFindings.unshift(finding);
    broadcastSSE('finding', finding);
  }

  // Update Asset last seen
  const existingAsset = registeredAssets.find(a => a.name === host || a.ip === host);
  if (existingAsset) {
    existingAsset.status = 'online';
    existingAsset.lastSeen = new Date().toISOString();
  } else if (host && host !== 'unknown-host') {
    registeredAssets.push({
      id: 'auto-' + (registeredAssets.length + 1),
      name: host,
      ip: host.includes('.') ? host : 'DHCP-Auto',
      mac: 'Auto-Discovered',
      os: sourcetype.includes('Win') ? 'Windows' : 'Linux / Unix',
      status: 'online',
      type: 'Workstation',
      risk: finding ? finding.risk : 10,
      owner: 'Auto-Registered Forwarder'
    });
  }

  broadcastSSE('log', logEntry);
  broadcastSSE('stats', { totalLogs: ingestedLogs.length, totalFindings: liveFindings.length, totalAssets: registeredAssets.length });
  return logEntry;
}

// MIME types
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// HTTP Server
const server = http.createServer((req, res) => {
  // Enable CORS for local cross-origin ingestion
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Splunk-Request-Channel');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = urlObj.pathname;

  // 1. Splunk HEC Endpoint: POST /services/collector/event or /services/collector
  if (pathname === '/services/collector/event' || pathname === '/services/collector' || pathname === '/services/collector/raw') {
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ text: 'Method Not Allowed', code: 405 }));
    }

    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        let host = req.socket.remoteAddress || '127.0.0.1';
        if (host.startsWith('::ffff:')) host = host.substring(7);
        let sourcetype = 'splunk:hec';

        // Check if JSON
        if (body.trim().startsWith('{')) {
          const parsed = JSON.parse(body);
          const eventText = typeof parsed.event === 'object' ? JSON.stringify(parsed.event) : String(parsed.event || body);
          if (parsed.host) host = parsed.host;
          if (parsed.sourcetype) sourcetype = parsed.sourcetype;
          processIncomingLog(eventText, host, sourcetype);
        } else {
          // Raw text lines
          body.split('\n').filter(Boolean).forEach(line => {
            processIncomingLog(line.trim(), host, 'syslog:raw');
          });
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ text: 'Success', code: 0, ackId: Date.now() }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ text: 'Invalid Data Format', code: 400, error: err.message }));
      }
    });
    return;
  }

  // 2. Real-Time SSE Stream: GET /api/stream
  if (pathname === '/api/stream') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });
    res.write(`event: init\ndata: ${JSON.stringify({ status: 'connected', hecToken: HEC_TOKEN, assets: registeredAssets, findings: liveFindings, logs: ingestedLogs.slice(0, 50) })}\n\n`);
    sseClients.push(res);
    req.on('close', () => {
      sseClients = sseClients.filter(c => c !== res);
    });
    return;
  }

  // 3. REST APIs
  if (pathname === '/api/logs/reset' && (req.method === 'POST' || req.method === 'GET')) {
    ingestedLogs = [];
    liveFindings = [];
    broadcastSSE('reset', { message: 'Logs reset to clean state' });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ success: true, message: 'Logs and simulated findings cleared.' }));
  }

  if (pathname === '/api/logs') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ logs: ingestedLogs }));
  }

  if (pathname === '/api/findings') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ findings: liveFindings }));
  }

  if (pathname === '/api/assets') {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const newAsset = JSON.parse(body);
          newAsset.id = 'asset-' + (registeredAssets.length + 1);
          newAsset.status = 'online';
          newAsset.risk = newAsset.risk || 10;
          registeredAssets.push(newAsset);
          broadcastSSE('assets', registeredAssets);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, asset: newAsset }));
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ assets: registeredAssets }));
  }

  // 4. Real Machine TCP Port Probe: POST /api/assets/probe
  if (pathname === '/api/assets/probe' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        const { target, port } = JSON.parse(body);
        const checkPort = port || 80;
        const sock = new net.Socket();
        sock.setTimeout(1500);

        sock.on('connect', () => {
          sock.destroy();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ target, port: checkPort, status: 'OPEN', reachable: true }));
        });
        sock.on('timeout', () => {
          sock.destroy();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ target, port: checkPort, status: 'FILTERED/TIMEOUT', reachable: false }));
        });
        sock.on('error', err => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ target, port: checkPort, status: 'CLOSED', error: err.message, reachable: false }));
        });

        sock.connect(checkPort, target);
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // 5. Static File Server
  let filePath = path.join(__dirname, pathname === '/' ? 'splunk.html' : pathname);
  if (!fs.existsSync(filePath)) {
    filePath = path.join(__dirname, 'splunk.html');
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
});

// Syslog UDP Server
const udpServer = dgram.createSocket('udp4');
udpServer.on('message', (msg, rinfo) => {
  const text = msg.toString('utf8').trim();
  const host = rinfo.address;
  console.log(`[Syslog UDP] Ingested from ${host}:${rinfo.port} -> ${text}`);
  processIncomingLog(text, host, 'syslog:udp');
});
udpServer.on('error', err => {
  console.log(`[Syslog UDP Warning] ${err.message}`);
});

// Start Servers
server.listen(HTTP_PORT, () => {
  console.log(`\n================================================================`);
  console.log(`  SHADOWXLAB · SPLUNK ENTERPRISE SECURITY STANDALONE INGESTION`);
  console.log(`================================================================`);
  console.log(`  ✓ Web & ES Mission Control: http://localhost:${HTTP_PORT}/splunk.html`);
  console.log(`  ✓ Splunk HEC Ingestion:     http://localhost:${HTTP_PORT}/services/collector/event`);
  console.log(`  ✓ HEC Token:                ${HEC_TOKEN}`);
  console.log(`  ✓ Real-Time SSE Stream:     http://localhost:${HTTP_PORT}/api/stream`);
  console.log(`  ✓ Asset Probe & Scan API:   http://localhost:${HTTP_PORT}/api/assets/probe`);
  
  try {
    udpServer.bind(SYSLOG_PORT, () => {
      console.log(`  ✓ Syslog UDP Listener:      udp://localhost:${SYSLOG_PORT}`);
    });
  } catch (e) {
    console.log(`  ! Syslog UDP port ${SYSLOG_PORT} not bound (may require elevated privileges).`);
  }
  console.log(`================================================================\n`);
});
