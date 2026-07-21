/* Dashboard widget system */
var dashboardState = { stats: null, layout: null, charts: {} };

function loadDashboard() {
    loadArchives();
    Promise.all([
        fetch('/api/dashboard/stats').then(r => r.json()),
        fetch('/api/dashboard/layout').then(r => r.json())
    ]).then(function(results) {
        dashboardState.stats = results[0];
        dashboardState.layout = results[1];
        renderWidgets();
    }).catch(function(e) {
        document.getElementById('widget-grid').innerHTML =
            '<div class="text-center py-16 text-gray-500"><p class="text-lg">Failed to load dashboard data</p><p class="text-sm mt-1">' + escapeHtml(e.message) + '</p></div>';
    });
}

function renderWidgets() {
    var grid = document.getElementById('widget-grid');
    var widgets = dashboardState.layout.widgets.filter(function(w) { return w.enabled; });
    if (widgets.length === 0) {
        grid.innerHTML =
            '<div class="text-center py-16 text-gray-500 col-span-2" id="no-widgets"><i data-lucide="layout-dashboard" class="w-12 h-12 mx-auto mb-4 opacity-30"></i><p class="text-lg">No widgets enabled</p><p class="text-sm mt-1">Click <strong>Customize</strong> to add widgets.</p></div>';
        lucide.createIcons();
        return;
    }
    grid.innerHTML = '';
    widgets.forEach(function(w, idx) {
        var el = document.createElement('div');
        el.className = 'widget-card bg-gray-900 border border-gray-800 rounded-lg ' +
            (w.width === 'full' ? 'widget-full' : 'widget-half');
        el.id = 'widget-' + w.id;
        el.setAttribute('data-widget-id', w.id);
        el.setAttribute('data-widget-title', w.title);
        el.innerHTML = buildWidgetContent(w);
        grid.appendChild(el);
    });
    // Render each widget type after DOM insertion
    widgets.forEach(function(w) {
        renderWidgetContent(w);
    });
    lucide.createIcons();
    if (dashboardState.stats.cases.total === 0) {
        showEmptyWidgets();
    }
}

function buildWidgetContent(w) {
    var html = '<div class="widget-header flex items-center justify-between px-4 py-3 border-b border-gray-800">' +
        '<h3 class="text-sm font-medium text-gray-200">' + escapeHtml(w.title) + '</h3>' +
        '<div class="flex items-center gap-1">' +
        '<span class="widget-loader text-xs text-gray-600 hidden">' +
        '<i data-lucide="loader" class="w-3.5 h-3.5 animate-spin inline-block"></i></span>' +
        '</div></div><div class="widget-body p-4">';
    switch (w.id) {
        case 'stats-bar':
            html += buildStatsBar();
            break;
        case 'severity-chart':
            html += '<canvas id="chart-severity" height="220"></canvas>';
            break;
        case 'status-chart':
            html += '<canvas id="chart-status" height="220"></canvas>';
            break;
        case 'recent-findings':
            html += buildRecentFindings();
            break;
        case 'case-overview':
            html += buildCaseOverview();
            break;
        case 'top-cves':
            html += '<canvas id="chart-cves" height="220"></canvas>';
            break;
        case 'finding-trend':
            html += buildFindingTrend();
            break;
        case 'recent-activity':
            html += buildRecentActivity();
            break;
        case 'recent-loot':
            html += '<div id="loot-placeholder" class="text-gray-500 text-sm text-center py-4"><i data-lucide="loader" class="w-5 h-5 mx-auto mb-2 animate-spin"></i><p>Loading loot...</p></div>';
            break;
        default:
            html += '<p class="text-gray-500 text-sm">Unknown widget</p>';
    }
    html += '</div>';
    return html;
}

function renderWidgetContent(w) {
    switch (w.id) {
        case 'severity-chart': renderSeverityChart(); break;
        case 'status-chart': renderStatusChart(); break;
        case 'top-cves': renderCveChart(); break;
        case 'recent-loot': renderRecentLoot(); break;
    }
}

/* Widget builders */

function buildStatsBar() {
    var s = dashboardState.stats;
    if (!s) return '<p class="text-gray-500 text-sm">Loading...</p>';
    var cases = s.cases, f = s.findings;
    var cards = [
        { label: 'Total Cases', value: cases.total, color: 'text-blue-400', icon: 'folder' },
        { label: 'Open Cases', value: cases.by_status.open || 0, color: 'text-green-400', icon: 'activity' },
        { label: 'Total Findings', value: f.total, color: 'text-indigo-400', icon: 'search' },
        { label: 'Critical', value: f.by_severity.critical || 0, color: 'text-red-400', icon: 'alert-triangle' },
        { label: 'High', value: f.by_severity.high || 0, color: 'text-orange-400', icon: 'chevron-up' },
        { label: 'Unvalidated', value: f.by_status.unvalidated || 0, color: 'text-yellow-400', icon: 'circle' },
    ];
    var html = '<div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">';
    cards.forEach(function(c) {
        html += '<div class="stat-card bg-gray-800/50 rounded-lg p-3 text-center hover:bg-gray-800 transition">' +
            '<div class="text-2xl font-bold ' + c.color + '">' + c.value + '</div>' +
            '<div class="text-xs text-gray-500 mt-1">' + c.label + '</div></div>';
    });
    html += '</div>';
    return html;
}

function buildRecentFindings() {
    var recent = dashboardState.stats.findings.recent;
    if (!recent || recent.length === 0) {
        return '<p class="text-gray-500 text-sm text-center py-4">No findings yet</p>';
    }
    var sevColors = { critical: 'bg-red-600', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-blue-500', info: 'bg-gray-500' };
    var html = '<div class="overflow-x-auto"><table class="w-full text-sm">' +
        '<thead><tr class="text-gray-500 text-xs uppercase">' +
        '<th class="text-left pb-2 font-medium">Severity</th>' +
        '<th class="text-left pb-2 font-medium">Title</th>' +
        '<th class="text-left pb-2 font-medium hidden md:table-cell">Case</th>' +
        '<th class="text-left pb-2 font-medium hidden md:table-cell">CVE</th>' +
        '<th class="text-right pb-2 font-medium">Status</th></tr></thead><tbody>';
    recent.forEach(function(f) {
        var sc = sevColors[f.severity] || 'bg-gray-500';
        html += '<tr class="border-t border-gray-800 hover:bg-gray-800/50 transition">' +
            '<td class="py-2"><span class="inline-block w-2 h-2 rounded-full ' + sc + '"></span>' +
            ' <span class="text-xs text-gray-400">' + f.severity + '</span></td>' +
            '<td class="py-2"><a href="/case/' + f._case_id + '/finding/' + f.id + '" class="text-gray-200 hover:text-indigo-400">' +
            escapeHtml(f.title || '?') + '</a></td>' +
            '<td class="py-2 hidden md:table-cell"><a href="/case/' + f._case_id + '" class="text-gray-500 hover:text-gray-300">' +
            escapeHtml(f._case_id) + '</a></td>' +
            '<td class="py-2 hidden md:table-cell">' + (f.cve ? '<span class="text-xs bg-red-900/30 text-red-400 px-1.5 py-0.5 rounded">' + f.cve + '</span>' : '') + '</td>' +
            '<td class="py-2 text-right"><span class="text-xs px-1.5 py-0.5 rounded ' +
            ({unvalidated:'bg-gray-800 text-gray-300', validated:'bg-indigo-900/50 text-indigo-300', remediated:'bg-green-900/50 text-green-300'}[f.status] || 'bg-gray-800 text-gray-400') + '">' +
            (f.status || 'unvalidated').replace('_', ' ') + '</span></td></tr>';
    });
    html += '</tbody></table></div>';
    return html;
}

function buildCaseOverview() {
    var casesList = dashboardState.stats.cases.list;
    if (!casesList || casesList.length === 0) {
        return '<p class="text-gray-500 text-sm text-center py-4">No cases yet</p>';
    }
    var html = '<div class="overflow-x-auto max-h-72 overflow-y-auto"><table class="w-full text-sm">' +
        '<thead><tr class="text-gray-500 text-xs uppercase sticky top-0 bg-gray-900">' +
        '<th class="text-left pb-2 font-medium">Case</th>' +
        '<th class="text-left pb-2 font-medium">Client</th>' +
        '<th class="text-left pb-2 font-medium hidden sm:table-cell">Type</th>' +
        '<th class="text-center pb-2 font-medium">Findings</th>' +
        '<th class="text-center pb-2 font-medium">Critical</th>' +
        '<th class="text-right pb-2 font-medium">Status</th></tr></thead><tbody>';
    casesList.forEach(function(c) {
        html += '<tr class="border-t border-gray-800 hover:bg-gray-800/50 transition">' +
            '<td class="py-2"><a href="/case/' + c.case_id + '" class="text-gray-200 hover:text-indigo-400 font-medium">' +
            escapeHtml(c.case_id) + '</a></td>' +
            '<td class="py-2 text-gray-400 text-xs">' + escapeHtml(c.client || '-') + '</td>' +
            '<td class="py-2 hidden sm:table-cell"><span class="text-xs text-gray-500">' + escapeHtml(c.type) + '</span></td>' +
            '<td class="py-2 text-center">' + c.findings + '</td>' +
            '<td class="py-2 text-center">' +
            (c.critical > 0 ? '<span class="text-red-400 font-medium">' + c.critical + '</span>' : '<span class="text-gray-600">0</span>') +
            '</td>' +
            '<td class="py-2 text-right"><span class="text-xs px-1.5 py-0.5 rounded ' +
            (c.status === 'open' ? 'bg-green-900/50 text-green-300' : 'bg-gray-800 text-gray-500') + '">' +
            c.status + '</span></td></tr>';
    });
    html += '</tbody></table></div>';
    return html;
}

function buildFindingTrend() {
    return '<div id="trend-placeholder" class="text-gray-500 text-sm text-center py-4">' +
        '<i data-lucide="bar-chart-3" class="w-8 h-8 mx-auto mb-2 opacity-40"></i>' +
        '<p>Enable this widget to track findings over time</p></div>';
}

function buildRecentActivity() {
    var activity = dashboardState.stats.recent_activity;
    if (!activity || activity.length === 0) {
        return '<p class="text-gray-500 text-sm text-center py-4">No recent activity</p>';
    }
    var html = '<div class="space-y-1 max-h-72 overflow-y-auto">';
    activity.forEach(function(a) {
        var icon = a.type === 'finding' ? 'search' : 'folder';
        var color = a.type === 'finding' ? 'text-indigo-400' : 'text-blue-400';
        html += '<div class="flex items-start gap-2 py-1.5 border-b border-gray-800/50 last:border-0">' +
            '<i data-lucide="' + icon + '" class="w-3.5 h-3.5 mt-0.5 ' + color + ' shrink-0"></i>' +
            '<div class="flex-1 min-w-0">' +
            '<div class="text-xs text-gray-300 truncate">' + escapeHtml(a.detail || '') + '</div>' +
            '<div class="text-[10px] text-gray-600">' + escapeHtml(a.client || '') + ' ' + (a.ts ? new Date(a.ts).toLocaleString() : '') + '</div>' +
            '</div>' +
            (a.severity ? '<span class="text-[10px] px-1 py-0.5 rounded ' +
                ({critical:'bg-red-900/40 text-red-300', high:'bg-orange-900/40 text-orange-300', medium:'bg-yellow-900/40 text-yellow-300', low:'bg-blue-900/40 text-blue-300'}[a.severity] || 'bg-gray-800 text-gray-400') + '">' + a.severity + '</span>' : '') +
            '</div>';
    });
    html += '</div>';
    return html;
}

function renderRecentLoot() {
    var container = document.getElementById('loot-placeholder');
    if (!container) return;
    fetch('/api/loot').then(function(r) { return r.json(); }).then(function(data) {
        var creds = data.credentials || [];
        if (!creds.length) {
            container.innerHTML = '<p class="text-gray-500 text-sm text-center py-4">No loot yet</p>';
            return;
        }
        var html = '<div class="space-y-1 max-h-72 overflow-y-auto">';
        creds.slice(0, 15).forEach(function(c) {
            html += '<div class="flex items-center gap-2 py-1.5 border-b border-gray-800/50 last:border-0 text-xs">' +
                '<i data-lucide="key" class="w-3.5 h-3.5 text-amber-400 shrink-0"></i>' +
                '<span class="text-gray-300 truncate max-w-[120px]">' + escapeHtml(c.username || '?') + '</span>' +
                '<span class="text-gray-600">@</span>' +
                '<span class="text-gray-400 truncate max-w-[160px]">' + escapeHtml(c.target || '?') + '</span>' +
                (c.protocol ? '<span class="text-[10px] bg-gray-800 text-gray-500 px-1 rounded">' + escapeHtml(c.protocol) + '</span>' : '') +
                '<span class="text-[10px] text-gray-600 ml-auto">' + (c.discovered ? new Date(c.discovered).toLocaleDateString() : '') + '</span>' +
                '</div>';
        });
        html += '</div>';
        container.innerHTML = html;
        if (window.lucide) lucide.createIcons();
    }).catch(function() {
        container.innerHTML = '<p class="text-gray-500 text-sm text-center py-4">Failed to load loot</p>';
    });
}

/* Chart rendering */

function renderSeverityChart() {
    var canvas = document.getElementById('chart-severity');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var sev = dashboardState.stats.findings.by_severity;
    var labels = ['critical', 'high', 'medium', 'low', 'info'];
    var colors = ['#dc2626', '#f97316', '#eab308', '#3b82f6', '#6b7280'];
    var data = labels.map(function(l) { return sev[l] || 0; });
    if (data.reduce(function(a, b) { return a + b; }, 0) === 0) {
        canvas.parentElement.innerHTML = '<p class="text-gray-500 text-sm text-center py-8">No findings yet</p>';
        return;
    }
    if (dashboardState.charts.severity) dashboardState.charts.severity.destroy();
    dashboardState.charts.severity = new Chart(ctx, {
        type: 'doughnut',
        data: { labels: labels, datasets: [{ data: data, backgroundColor: colors, borderWidth: 0 }] },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { color: '#9ca3af', padding: 12, font: { size: 11 } } }
            }
        }
    });
}

function renderStatusChart() {
    var canvas = document.getElementById('chart-status');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');
    var st = dashboardState.stats.findings.by_status;
    var labels = Object.keys(st);
    var colors = { unvalidated: '#6b7280', validated: '#6366f1', remediated: '#22c55e', closed_other: '#374151' };
    var data = labels.map(function(l) { return st[l]; });
    var bg = labels.map(function(l) { return colors[l] || '#6b7280'; });
    if (data.reduce(function(a, b) { return a + b; }, 0) === 0) {
        canvas.parentElement.innerHTML = '<p class="text-gray-500 text-sm text-center py-8">No findings yet</p>';
        return;
    }
    if (dashboardState.charts.status) dashboardState.charts.status.destroy();
    dashboardState.charts.status = new Chart(ctx, {
        type: 'doughnut',
        data: { labels: labels, datasets: [{ data: data, backgroundColor: bg, borderWidth: 0 }] },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { color: '#9ca3af', padding: 12, font: { size: 11 } } }
            }
        }
    });
}

function renderCveChart() {
    var canvas = document.getElementById('chart-cves');
    if (!canvas) return;
    var cves = dashboardState.stats.top_cves;
    var keys = Object.keys(cves);
    if (keys.length === 0) {
        canvas.parentElement.innerHTML = '<p class="text-gray-500 text-sm text-center py-8">No CVEs tracked</p>';
        return;
    }
    var labels = keys.slice(0, 8);
    var data = labels.map(function(k) { return cves[k]; });
    if (dashboardState.charts.cves) dashboardState.charts.cves.destroy();
    var ctx = canvas.getContext('2d');
    dashboardState.charts.cves = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{ data: data, backgroundColor: '#6366f1', borderRadius: 4 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: { ticks: { color: '#6b7280', font: { size: 10 } }, grid: { color: '#1f2937' } },
                y: { ticks: { color: '#9ca3af', font: { size: 10 } }, grid: { display: false } }
            }
        }
    });
}

/* Empty state when no cases exist */
function showEmptyWidgets() {
    var grid = document.getElementById('widget-grid');
    var children = grid.querySelectorAll('.widget-card');
    children.forEach(function(el) {
        var body = el.querySelector('.widget-body');
        if (body && !body.querySelector('canvas')) {
            body.innerHTML = '<p class="text-gray-500 text-sm text-center py-4">No data yet — create a case to get started</p>';
        }
    });
}

/* Customization modal */
function customizeDashboard() {
    var modal = document.getElementById('customize-modal');
    modal.classList.remove('hidden');
    var list = document.getElementById('customize-widget-list');
    var widgets = dashboardState.layout.widgets;
    list.innerHTML = '';
    widgets.forEach(function(w, idx) {
        var row = document.createElement('div');
        row.className = 'flex items-center justify-between py-2 px-3 rounded hover:bg-gray-800/50 cursor-move';
        row.setAttribute('data-widget-idx', idx);
        row.innerHTML =
            '<div class="flex items-center gap-3">' +
            '<i data-lucide="grip-vertical" class="w-4 h-4 text-gray-600 drag-handle"></i>' +
            '<span class="text-sm text-gray-200">' + escapeHtml(w.title) + '</span></div>' +
            '<label class="relative inline-flex items-center cursor-pointer">' +
            '<input type="checkbox" class="sr-only peer widget-toggle" data-widget-id="' + w.id + '" ' +
            (w.enabled ? 'checked' : '') + '>' +
            '<div class="w-9 h-5 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[\'\'] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600"></div>' +
            '</label></div>';
        list.appendChild(row);
    });
    lucide.createIcons();
    // Initialize Sortable on the list
    if (window.Sortable && window._sortableInstance) window._sortableInstance.destroy();
    if (window.Sortable) {
        window._sortableInstance = new Sortable(list, {
            handle: '.drag-handle',
            animation: 150,
            onEnd: function() {
                // Reorder will be captured on save
            }
        });
    }
}

function saveDashboardLayout() {
    var list = document.getElementById('customize-widget-list');
    var rows = list.querySelectorAll('[data-widget-idx]');
    var newOrder = [];
    rows.forEach(function(row) {
        var idx = parseInt(row.getAttribute('data-widget-idx'));
        var toggle = row.querySelector('.widget-toggle');
        var w = dashboardState.layout.widgets[idx];
        w.enabled = toggle.checked;
        newOrder.push(w);
    });
    dashboardState.layout.widgets = newOrder;
    fetch('/api/dashboard/layout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ widgets: newOrder })
    }).then(function(r) {
        if (r.ok) {
            closeCustomizeModal();
            renderWidgets();
        } else {
            alert('Failed to save layout');
        }
    }).catch(function(e) {
        alert('Error: ' + e.message);
    });
}

function closeCustomizeModal() {
    document.getElementById('customize-modal').classList.add('hidden');
}

/* Esc key closes customize modal */
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeCustomizeModal();
});
