/* WiFi Monitor — live airodump-ng dashboard */
var monState = { running: false, session_id: null, pollTimer: null, charts: {},
    sort: {
        ap: { key: 'signal', dir: 'desc' },
        client: { key: 'signal', dir: 'desc' },
    }
};

document.addEventListener('DOMContentLoaded', function() {
    loadInterfaces();
    loadPastSessions();
    initTableSort('#ap-table thead tr', 'ap', [
        {key:'bssid', dir:''}, {key:'essid', dir:''}, {key:'channel', dir:''},
        {key:'signal', dir:'desc'}, {key:'encryption', dir:''}, {key:'wps', dir:''}, {key:'', dir:''}
    ]);
    initTableSort('#client-table thead tr', 'client', [
        {key:'mac', dir:''}, {key:'signal', dir:'desc'}, {key:'bssid', dir:''},
        {key:'probed_essids', dir:''}, {key:'packets', dir:''}
    ]);
    // Auto-connect to any running session
    fetch('/api/wifi/monitor/status').then(function(r) { return r.json(); }).then(function(s) {
        if (s.status === 'running') {
            monState.session_id = s.session_id;
            monState.running = true;
            document.getElementById('btn-start').disabled = true;
            document.getElementById('btn-stop').disabled = false;
            document.getElementById('btn-force-stop').disabled = false;
            document.getElementById('btn-deauth').disabled = false;
            document.getElementById('mon-stats').classList.remove('hidden');
            document.getElementById('mon-content').classList.remove('hidden');
            updateStatus();
            monState.pollTimer = setInterval(pollData, 2000);
        }
    }).catch(function() {});
});

function initTableSort(selector, tableName, columns) {
    var headers = document.querySelectorAll(selector + ' th');
    headers.forEach(function(th, i) {
        if (i >= columns.length || !columns[i].key) return;
        th.style.cursor = 'pointer';
        th.title = 'Click to sort';
        th.addEventListener('click', function() {
            var col = columns[i];
            var cur = monState.sort[tableName];
            if (cur.key === col.key) {
                cur.dir = cur.dir === 'asc' ? 'desc' : 'asc';
            } else {
                cur.key = col.key;
                cur.dir = col.dir || 'asc';
            }
            // Update header indicators
            headers.forEach(function(h) { h.textContent = h.textContent.replace(/ [▲▼]$/, ''); });
            th.textContent = th.textContent.replace(/ [▲▼]$/, '') + ' ' + (cur.dir === 'asc' ? '▲' : '▼');
            // Re-render
            if (tableName === 'ap') renderAPs(window._lastAps || []);
            else renderClients(window._lastClients || []);
        });
        // Initial indicator
        if (columns[i].key === monState.sort[tableName].key) {
            var dir = monState.sort[tableName].dir;
            th.textContent = th.textContent.trim() + ' ' + (dir === 'asc' ? '▲' : '▼');
        }
    });
}

function doSort(data, sortKey, sortDir, parseFn) {
    if (!sortKey) return data;
    return data.slice().sort(function(a, b) {
        var va = parseFn ? parseFn(a[sortKey]) : a[sortKey];
        var vb = parseFn ? parseFn(b[sortKey]) : b[sortKey];
        if (va === undefined || va === null) va = '';
        if (vb === undefined || vb === null) vb = '';
        var cmp = 0;
        if (typeof va === 'number' && typeof vb === 'number') {
            cmp = va - vb;
        } else {
            cmp = String(va).localeCompare(String(vb));
        }
        return sortDir === 'desc' ? -cmp : cmp;
    });
}

function loadInterfaces() {
    fetch('/api/wifi/monitor/interfaces').then(function(r) { return r.json(); })
    .then(function(ifaces) {
        var sel = document.getElementById('mon-iface');
        ifaces.forEach(function(iface) {
            var opt = document.createElement('option');
            opt.value = iface;
            opt.textContent = iface;
            sel.appendChild(opt);
        });
    }).catch(function() {
        var sel = document.getElementById('mon-iface');
        sel.innerHTML = '<option value="wlan0">wlan0</option>';
    });
}

function startMonitor() {
    var btn = document.getElementById('btn-start');
    btn.disabled = true;
    btn.innerHTML = '<i data-lucide="loader" class="w-4 h-4 animate-spin inline-block"></i> Starting...';
    fetch('/api/wifi/monitor/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            iface: document.getElementById('mon-iface').value,
            band: document.getElementById('mon-band').value,
            target_bssid: document.getElementById('mon-bssid').value.trim(),
            target_essid: document.getElementById('mon-essid').value.trim(),
        })
    }).then(function(r) { return r.json(); }).then(function(data) {
        if (data.error) {
            alert('Error: ' + data.error);
            btn.disabled = false;
            btn.innerHTML = '<i data-lucide="play" class="w-4 h-4"></i> Start';
            lucide.createIcons();
            return;
        }
        monState.session_id = data.session_id;
        monState.running = true;
        document.getElementById('btn-start').disabled = true;
        document.getElementById('btn-stop').disabled = false;
        document.getElementById('btn-force-stop').disabled = false;
        document.getElementById('btn-deauth').disabled = false;
        document.getElementById('mon-stats').classList.remove('hidden');
        document.getElementById('mon-content').classList.remove('hidden');
        updateStatus();
        monState.pollTimer = setInterval(pollData, 2000);
    }).catch(function(e) {
        alert('Error: ' + e.message);
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="play" class="w-4 h-4"></i> Start';
        lucide.createIcons();
    });
}

function stopMonitor(force) {
    if (force === undefined) force = false;
    var msg = force ? 'Force kill WiFi session? (may leave interface in bad state)' : 'Stop WiFi monitoring session?';
    if (!confirm(msg)) return;
    clearInterval(monState.pollTimer);
    fetch('/api/wifi/monitor/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: monState.session_id, force: force })
    }).then(function(r) { return r.json(); }).then(function(data) {
        if (data.error) {
            alert('Error stopping session: ' + data.error);
            return;
        }
        monState.running = false;
        document.getElementById('btn-start').disabled = false;
        document.getElementById('btn-stop').disabled = true;
        document.getElementById('btn-force-stop').disabled = true;
        document.getElementById('btn-deauth').disabled = true;
        document.getElementById('status-indicator').className = 'inline-block w-2 h-2 rounded-full bg-yellow-500';
        document.getElementById('status-text').textContent = force ? 'Force killed' : 'Stopped';
        document.getElementById('uptime-text').classList.add('hidden');
        loadPastSessions();
    }).catch(function(e) {
        alert('Error: ' + e.message);
    });
}

function updateStatus() {
    if (!monState.running) return;
    fetch('/api/wifi/monitor/status' + (monState.session_id ? '?session_id=' + monState.session_id : ''))
    .then(function(r) { return r.json(); }).then(function(s) {
        if (s.status === 'running') {
            document.getElementById('status-indicator').className = 'inline-block w-2 h-2 rounded-full bg-green-500 animate-pulse';
            document.getElementById('status-text').textContent = 'Monitoring ' + s.iface;
            var uptimeEl = document.getElementById('uptime-text');
            if (s.uptime) {
                uptimeEl.textContent = '(' + s.uptime + ')';
                uptimeEl.classList.remove('hidden');
            }
            if (s.aps_count !== undefined) document.getElementById('stat-aps').textContent = s.aps_count;
            if (s.clients_count !== undefined) document.getElementById('stat-clients').textContent = s.clients_count;
            if (s.captures) {
                document.getElementById('stat-handshakes').textContent = s.captures.handshakes || 0;
                document.getElementById('stat-pmkid').textContent = s.captures.pmkids || 0;
                document.getElementById('stat-strings').textContent = s.captures.packet_strings || 0;
            }
            if (s.stats) {
                document.getElementById('stat-beacons').textContent = s.stats.beacons_total || 0;
                document.getElementById('stat-packets').textContent = s.stats.total_packets || 0;
            }
        } else if (s.status === 'stopped') {
            document.getElementById('status-indicator').className = 'inline-block w-2 h-2 rounded-full bg-yellow-500';
            document.getElementById('status-text').textContent = 'Stopped';
        } else {
            document.getElementById('status-indicator').className = 'inline-block w-2 h-2 rounded-full bg-gray-600';
            document.getElementById('status-text').textContent = 'Idle';
        }
    }).catch(function() {});
}

function pollData() {
    if (!monState.running) return;
    updateStatus();
    fetch('/api/wifi/monitor/data' + (monState.session_id ? '?session_id=' + monState.session_id : ''))
    .then(function(r) { return r.json(); }).then(function(data) {
        if (data.error) return;
        renderAPs(data.aps || []);
        renderClients(data.clients || []);
        renderSignalChart(data.signal_history || {});
        renderChannelChart(data.aps || []);
        renderCaptures(data.captures || {});
    }).catch(function() {});
}

function renderAPs(aps) {
    window._lastAps = aps;
    var tbody = document.getElementById('ap-table-body');
    document.getElementById('ap-count').textContent = '(' + aps.length + ')';
    if (aps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4 text-gray-600">No APs found</td></tr>';
        return;
    }
    tbody.innerHTML = '';
    var s = monState.sort.ap;
    var sorted = doSort(aps, s.key, s.dir, function(v) {
        if (s.key === 'signal') return v === null ? -999 : v;
        if (s.key === 'channel') return parseInt(v) || 0;
        return v;
    });
    sorted.forEach(function(ap) {
        var signalColor = 'text-gray-400';
        if (ap.signal >= -50) signalColor = 'text-green-400';
        else if (ap.signal >= -70) signalColor = 'text-yellow-400';
        else if (ap.signal !== null) signalColor = 'text-red-400';
        var signalStr = ap.signal !== null && ap.signal !== undefined ? ap.signal + ' dBm' : '?';
        var wpsBadge = ap.wps ? '<span class="text-green-400">&#10003;</span>' : '<span class="text-gray-700">-</span>';
        var tr = document.createElement('tr');
        tr.className = 'border-t border-gray-800 hover:bg-gray-800/50';
        tr.innerHTML =
            '<td class="px-2 py-1.5 font-mono text-gray-300">' + escapeHtml(ap.bssid) + '</td>' +
            '<td class="px-2 py-1.5 text-gray-200">' + escapeHtml(ap.essid) + '</td>' +
            '<td class="px-2 py-1.5 text-center text-gray-400">' + ap.channel + '</td>' +
            '<td class="px-2 py-1.5 text-center ' + signalColor + '">' + signalStr + '</td>' +
            '<td class="px-2 py-1.5 text-center text-gray-400">' + escapeShort(ap.encryption) + '</td>' +
            '<td class="px-2 py-1.5 text-center">' + wpsBadge + '</td>' +
            '<td class="px-2 py-1.5 text-center text-gray-400">0</td>';
        tbody.appendChild(tr);
    });
}

function renderClients(clients) {
    window._lastClients = clients;
    var tbody = document.getElementById('client-table-body');
    document.getElementById('client-count').textContent = '(' + clients.length + ')';
    if (clients.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-gray-600">No clients found</td></tr>';
        return;
    }
    tbody.innerHTML = '';
    var s = monState.sort.client;
    var sorted = doSort(clients, s.key, s.dir, function(v) {
        if (s.key === 'signal') return v === null ? -999 : v;
        if (s.key === 'packets') return parseInt(v) || 0;
        return v;
    });
    sorted.forEach(function(cl) {
        var signalColor = 'text-gray-400';
        if (cl.signal >= -50) signalColor = 'text-green-400';
        else if (cl.signal >= -70) signalColor = 'text-yellow-400';
        else if (cl.signal !== null) signalColor = 'text-red-400';
        var signalStr = cl.signal !== null && cl.signal !== undefined ? cl.signal + ' dBm' : '?';
        var probes = cl.probed_essids ? cl.probed_essids.join(', ') : '';
        var tr = document.createElement('tr');
        tr.className = 'border-t border-gray-800 hover:bg-gray-800/50';
        tr.innerHTML =
            '<td class="px-2 py-1.5 font-mono text-gray-300">' + escapeHtml(cl.mac) + '</td>' +
            '<td class="px-2 py-1.5 text-center ' + signalColor + '">' + signalStr + '</td>' +
            '<td class="px-2 py-1.5 font-mono text-gray-500">' + escapeHtml(cl.bssid || '-') + '</td>' +
            '<td class="px-2 py-1.5 text-gray-400 max-w-[120px] truncate">' + escapeHtml(probes) + '</td>' +
            '<td class="px-2 py-1.5 text-center text-gray-400">' + (cl.packets || 0) + '</td>';
        tbody.appendChild(tr);
    });
}

function renderSignalChart(history) {
    var canvas = document.getElementById('chart-signal');
    if (!canvas) return;
    var bssids = Object.keys(history);
    if (bssids.length === 0) {
        if (monState.charts.signal) { monState.charts.signal.destroy(); monState.charts.signal = null; }
        return;
    }
    var ctx = canvas.getContext('2d');
    var colors = ['#6366f1', '#22c55e', '#f97316', '#ef4444', '#a855f7', '#06b6d4', '#eab308', '#ec4899'];
    var datasets = [];
    bssids.slice(0, 8).forEach(function(bssid, i) {
        var pts = history[bssid];
        if (!pts || pts.length < 2) return;
        var label = bssid.substring(0, 17);
        var data = pts.map(function(p) { return { x: p.ts, y: p.signal }; });
        datasets.push({
            label: label,
            data: data,
            borderColor: colors[i % colors.length],
            backgroundColor: colors[i % colors.length] + '20',
            borderWidth: 1.5,
            pointRadius: 1,
            tension: 0.3,
            fill: false,
        });
    });
    if (datasets.length === 0) return;
    if (monState.charts.signal) monState.charts.signal.destroy();
    monState.charts.signal = new Chart(ctx, {
        type: 'line',
        data: { datasets: datasets },
        options: {
            responsive: true, maintainAspectRatio: false,
            animation: false,
            scales: {
                x: {
                    type: 'time', time: { displayFormats: { second: 'HH:mm:ss' } },
                    ticks: { color: '#6b7280', maxTicksLimit: 10, font: { size: 10 } },
                    grid: { color: '#1f2937' },
                },
                y: {
                    reverse: true,
                    ticks: { color: '#6b7280', font: { size: 10 }, callback: function(v) { return v + ' dBm'; } },
                    grid: { color: '#1f2937' },
                }
            },
            plugins: {
                legend: { position: 'top', labels: { color: '#9ca3af', boxWidth: 12, padding: 8, font: { size: 10 } } },
            },
        }
    });
}

function renderChannelChart(aps) {
    var canvas = document.getElementById('chart-channel');
    if (!canvas) return;
    var channels = {};
    aps.forEach(function(ap) {
        var ch = ap.channel || '?';
        channels[ch] = (channels[ch] || 0) + 1;
    });
    var labels = Object.keys(channels).sort(function(a, b) { return parseInt(a) - parseInt(b); });
    var data = labels.map(function(l) { return channels[l]; });
    if (data.length === 0) {
        if (monState.charts.channel) { monState.charts.channel.destroy(); monState.charts.channel = null; }
        return;
    }
    var ctx = canvas.getContext('2d');
    if (monState.charts.channel) monState.charts.channel.destroy();
    monState.charts.channel = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: '#6366f1',
                borderRadius: 3,
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            animation: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#6b7280', font: { size: 10 } }, grid: { display: false } },
                y: { ticks: { color: '#6b7280', font: { size: 10 } }, grid: { color: '#1f2937' }, beginAtZero: true }
            }
        }
    });
}

function renderCaptures(captures) {
    var log = document.getElementById('capture-log');
    var events = [];
    (captures.handshakes || []).forEach(function(h) {
        events.push({
            ts: h.ts || '',
            icon: '&#128274;',
            text: 'Handshake: ' + escapeHtml(h.ap) + ' &harr; ' + escapeHtml(h.client),
        });
    });
    (captures.pmkids || []).forEach(function(p) {
        events.push({
            ts: p.ts || '',
            icon: '&#128273;',
            text: 'PMKID: ' + escapeHtml(p.ap),
        });
    });
    (captures.eap_identities || []).forEach(function(e) {
        events.push({
            ts: e.ts || '',
            icon: '&#128100;',
            text: 'EAP Identity: ' + escapeHtml(e.mac) + ' = ' + escapeHtml(e.identity),
        });
    });
    (captures.packet_strings || []).forEach(function(s) {
        var srcIcon = s.src === 'http' ? '&#127760;' : s.src === 'dns' ? '&#128220;' : s.src === 'dhcp' ? '&#128295;' : s.src === 'arp' ? '&#128279;' : '&#128196;';
        events.push({
            ts: s.ts || '',
            icon: srcIcon,
            text: escapeHtml(s.text.substring(0, 120)) + (s.text.length > 120 ? '...' : ''),
        });
    });
    events.sort(function(a, b) { return (b.ts || '').localeCompare(a.ts || ''); });
    if (events.length === 0) {
        log.innerHTML = '<p class="text-gray-600">No captures yet. Start monitoring to see events.</p>';
        return;
    }
    log.innerHTML = events.slice(0, 50).map(function(e) {
        var ts = e.ts.substring(11, 19) || '';
        return '<div class="flex gap-2"><span class="text-gray-600 w-16 shrink-0">' + ts + '</span><span>' + e.icon + ' ' + e.text + '</span></div>';
    }).join('');
}

function parsePcap() {
    fetch('/api/wifi/monitor/parse-pcap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: monState.session_id })
    }).then(function(r) { return r.json(); }).then(function(data) {
        if (data.error) { alert('Parse error: ' + data.error); return; }
        var msg = 'PCAP parsed: ';
        if (data.new_handshakes > 0) msg += data.new_handshakes + ' new handshake(s), ';
        if (data.new_pmkids > 0) msg += data.new_pmkids + ' new PMKID(s), ';
        if (data.new_eap > 0) msg += data.new_eap + ' new identity(ies), ';
        if (data.new_packet_strings > 0) msg += data.new_packet_strings + ' new string(s), ';
        msg = msg.replace(/, $/, '') || 'No new captures found';
        pollData();
    }).catch(function(e) { alert('Error: ' + e.message); });
}

function loadPastSessions() {
    fetch('/api/wifi/monitor/sessions').then(function(r) { return r.json(); }).then(function(sessions) {
        var el = document.getElementById('past-sessions');
        if (!sessions || sessions.length === 0) {
            el.innerHTML = '<span class="text-gray-600">No past sessions</span>';
            return;
        }
        var html = '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">';
        sessions.slice(0, 12).forEach(function(s) {
            html += '<div class="bg-gray-900 border border-gray-800 rounded p-2 text-xs hover:border-gray-700 transition cursor-pointer" onclick="loadSession(\'' + s.session_id + '\')">' +
                '<div class="font-medium text-gray-300">' + escapeHtml(s.session_id) + '</div>' +
                '<div class="text-gray-500 mt-1">' + s.iface + ' &middot; ' + (s.started || '').substring(0, 16) + '</div>' +
                '<div class="flex gap-2 mt-1"><span class="text-blue-400">' + s.aps + ' APs</span>' +
                '<span class="text-green-400">' + s.clients + ' clients</span>' +
                '<span class="text-indigo-400">' + s.handshakes + ' HS</span></div></div>';
        });
        html += '</div>';
        el.innerHTML = html;
    }).catch(function() {
        document.getElementById('past-sessions').innerHTML = '<span class="text-gray-600">Failed to load</span>';
    });
}

function loadSession(sessionId) {
    if (monState.running) {
        if (!confirm('Loading a past session will stop the current monitoring. Continue?')) return;
        stopMonitor();
    }
    monState.session_id = sessionId;
    document.getElementById('mon-stats').classList.remove('hidden');
    document.getElementById('mon-content').classList.remove('hidden');
    clearInterval(monState.pollTimer);
    // Load session data, then check if still running and poll
    fetch('/api/wifi/monitor/data?session_id=' + sessionId)
    .then(function(r) { return r.json(); }).then(function(data) {
        if (data.error) { return; }
        renderAPs(data.aps || []);
        renderClients(data.clients || []);
        renderSignalChart(data.signal_history || {});
        renderChannelChart(data.aps || []);
        renderCaptures(data.captures || {});
        document.getElementById('status-indicator').className = 'inline-block w-2 h-2 rounded-full bg-yellow-500';
        document.getElementById('status-text').textContent = 'Viewing: ' + sessionId;
        // Check if session is still running and poll live
        fetch('/api/wifi/monitor/status?session_id=' + sessionId)
        .then(function(r) { return r.json(); }).then(function(s) {
            if (s.status === 'running') {
                document.getElementById('status-indicator').className = 'inline-block w-2 h-2 rounded-full bg-green-500 animate-pulse';
                document.getElementById('status-text').textContent = 'Monitoring ' + s.iface;
                monState.running = true;
                updateStatus();
                monState.pollTimer = setInterval(pollData, 2000);
            } else {
                monState.running = false;
            }
        }).catch(function() { monState.running = false; });
    }).catch(function() { });
}

function showDeauthDialog() {
    var list = document.getElementById('deauth-aps-list');
    list.innerHTML = '<p class="text-gray-500 p-3">Loading APs...</p>';
    // Fetch latest AP data to populate the list
    fetch('/api/wifi/monitor/data' + (monState.session_id ? '?session_id=' + monState.session_id : ''))
    .then(function(r) { return r.json(); }).then(function(data) {
        var aps = data.aps || [];
        document.getElementById('deauth-bssid').value = '';
        document.getElementById('deauth-client').value = '';
        document.getElementById('deauth-count').value = '5';
        if (aps.length === 0) {
            list.innerHTML = '<p class="text-gray-500 p-3">No APs found. Enter BSSID manually.</p>';
        } else {
            var html = '<table class="w-full text-xs"><thead><tr class="text-gray-500 uppercase bg-gray-800 sticky top-0">' +
                '<th class="text-left px-2 py-1.5">BSSID</th><th class="text-left px-2 py-1.5">ESSID</th><th class="text-center px-2 py-1.5">CH</th><th class="text-center px-2 py-1.5">Signal</th><th class="text-center px-2 py-1.5"></th></tr></thead><tbody>';
            aps.forEach(function(ap) {
                html += '<tr class="border-t border-gray-800 hover:bg-gray-800/50 cursor-pointer" onclick="selectDeauthAP(\'' + escapeHtml(ap.bssid) + '\')">' +
                    '<td class="px-2 py-1.5 font-mono text-gray-300">' + escapeHtml(ap.bssid) + '</td>' +
                    '<td class="px-2 py-1.5 text-gray-200">' + escapeHtml(ap.essid) + '</td>' +
                    '<td class="px-2 py-1.5 text-center text-gray-400">' + (ap.channel || '-') + '</td>' +
                    '<td class="px-2 py-1.5 text-center text-gray-400">' + (ap.signal || '?') + '</td>' +
                    '<td class="px-2 py-1.5 text-center"><button class="text-orange-400 hover:text-orange-300 text-xs">Select</button></td></tr>';
            });
            html += '</tbody></table>';
            list.innerHTML = html;
        }
        document.getElementById('deauth-modal').classList.remove('hidden');
        lucide.createIcons();
    }).catch(function() {
        list.innerHTML = '<p class="text-gray-500 p-3">Failed to load APs. Enter BSSID manually.</p>';
        document.getElementById('deauth-modal').classList.remove('hidden');
    });
}

function hideDeauthDialog() {
    document.getElementById('deauth-modal').classList.add('hidden');
}

function selectDeauthAP(bssid) {
    document.getElementById('deauth-bssid').value = bssid;
}

function sendDeauth() {
    var btn = document.getElementById('btn-send-deauth');
    btn.disabled = true;
    btn.innerHTML = '<i data-lucide="loader" class="w-3 h-3 animate-spin inline-block"></i> Sending...';
    lucide.createIcons();
    fetch('/api/wifi/monitor/deauth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            session_id: monState.session_id,
            bssid: document.getElementById('deauth-bssid').value.trim(),
            client: document.getElementById('deauth-client').value.trim(),
            count: parseInt(document.getElementById('deauth-count').value) || 5,
        })
    }).then(function(r) { return r.json(); }).then(function(data) {
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="send" class="w-3 h-3"></i> Send Deauth';
        lucide.createIcons();
        if (data.error) { alert('Deauth error: ' + data.error); return; }
        if (data.status === 'error') { alert('Deauth failed: ' + (data.error || 'unknown')); return; }
        var msg = 'Deauth sent to ' + data.target_bssid;
        if (data.target_client) msg += ' (client: ' + data.target_client + ')';
        msg += ' - ' + data.packets_sent + ' packets';
        hideDeauthDialog();
        // Re-fetch data to show any new captures
        setTimeout(function() { pollData(); }, 2000);
    }).catch(function(e) {
        btn.disabled = false;
        btn.innerHTML = '<i data-lucide="send" class="w-3 h-3"></i> Send Deauth';
        lucide.createIcons();
        alert('Error: ' + e.message);
    });
}

function escapeHtml(t) {
    if (!t) return '';
    return String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function escapeShort(t) {
    if (!t) return '-';
    return t.substring(0, 8);
}
