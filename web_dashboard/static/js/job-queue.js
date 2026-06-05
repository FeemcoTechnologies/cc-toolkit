/* Job Queue — SSE client + floating widget */

(function () {
  'use strict';

  const STATE = { jobs: {}, listeners: {} };
  let eventSource = null;

  // --- Icons (inline SVG to avoid icon library dependency) ---
  const ICONS = {
    queued: '<span class="text-gray-400">&#x23F3;</span>',
    running: '<span class="text-blue-400 animate-pulse">&#x2699;</span>',
    completed: '<span class="text-green-400">&#x2714;</span>',
    failed: '<span class="text-red-400">&#x2716;</span>',
    cancelled: '<span class="text-yellow-400">&#x23F9;</span>',
  };
  const STATUS_ORDER = { queued: 0, running: 1, completed: 2, failed: 2, cancelled: 2 };

  // --- SSE connection ---
  function connectSSE(jobIds) {
    if (eventSource) {
      eventSource.close();
    }
    const params = jobIds && jobIds.length ? '?job_ids=' + encodeURIComponent(jobIds.join(',')) : '';
    eventSource = new EventSource('/api/jobs/stream' + params);
    eventSource.addEventListener('snapshot', function (e) {
      const jobs = JSON.parse(e.data);
      jobs.forEach(function (j) { STATE.jobs[j.id] = j; });
      renderWidget();
    });
    eventSource.addEventListener('message', function (e) {
      var data;
      try { data = JSON.parse(e.data); } catch (_) { return; }
      STATE.jobs[data.id] = data;
      renderWidget();
      // toast on state change
      var prev = STATE.jobs[data.id];
      if (data.status === 'completed' || data.status === 'failed') {
        showToast(data);
      }
    });
    eventSource.onerror = function () {
      // reconnect after 3s
      setTimeout(function () { connectSSE(jobIds); }, 3000);
    };
  }

  // --- Toast notification ---
  function showToast(job) {
    var toast = document.createElement('div');
    var cls = job.status === 'completed' ? 'bg-green-800 border-green-600' : 'bg-red-800 border-red-600';
    toast.className =
      'fixed bottom-20 right-4 z-50 border px-4 py-2 rounded shadow-lg text-sm text-white transition-all duration-300 ' +
      cls;
    toast.innerHTML =
      '<strong>' + (ICONS[job.status] || '') + ' ' + escapeHtml(job.title) + '</strong> — ' + escapeHtml(job.message || job.status);
    document.body.appendChild(toast);
    setTimeout(function () {
      toast.style.opacity = '0';
      setTimeout(function () { toast.remove(); }, 300);
    }, 4000);
  }

  // --- Widget rendering ---
  function renderWidget() {
    var container = document.getElementById('job-queue-widget');
    if (!container) return;
    var jobs = Object.values(STATE.jobs)
      .sort(function (a, b) { return a.created_at < b.created_at ? 1 : -1; })
      .slice(0, 20);
    if (!jobs.length) {
      container.innerHTML =
        '<div class="text-gray-500 text-xs p-3 text-center">No recent jobs</div>';
      return;
    }
    var html = '';
    var runningCount = 0;
    jobs.forEach(function (j) {
      if (j.status === 'running' || j.status === 'queued') runningCount++;
      html += renderJobRow(j);
    });
    container.innerHTML = html;

    // update badge
    var badge = document.getElementById('job-badge');
    if (badge) {
      badge.textContent = runningCount || '';
      badge.style.display = runningCount ? 'flex' : 'none';
    }
  }

  function renderJobRow(j) {
    var icon = ICONS[j.status] || '<span class="text-gray-400">?</span>';
    var pct = j.progress || 0;
    var barColor = j.status === 'failed' ? 'bg-red-500'
      : j.status === 'completed' ? 'bg-green-500'
        : j.status === 'cancelled' ? 'bg-yellow-500'
          : 'bg-indigo-500';
    var bgColor = j.status === 'running' || j.status === 'queued' ? 'bg-gray-800/80' : 'bg-gray-800/40';
    return '<div class="job-row ' + bgColor + ' border-b border-gray-700/50 p-2 text-xs hover:bg-gray-700/30 transition-colors">' +
      '<div class="flex items-center justify-between mb-1">' +
      '<span class="truncate flex-1">' + icon + ' ' + escapeHtml(j.title) + '</span>' +
      '<span class="text-gray-400 ml-2 whitespace-nowrap">' + pct + '%</span>' +
      (j.status === 'running'
        ? '<button class="ml-2 text-gray-500 hover:text-red-400" onclick="cancelJob(\'' + j.id + '\')" title="Cancel">&#x2715;</button>'
        : '') +
      '</div>' +
      (j.message ? '<div class="text-gray-500 truncate mb-1">' + escapeHtml(j.message) + '</div>' : '') +
      '<div class="w-full h-1 bg-gray-700 rounded-full overflow-hidden">' +
      '<div class="h-full ' + barColor + ' rounded-full transition-all duration-300" style="width:' + pct + '%"></div>' +
      '</div>' +
      '</div>';
  }

  // --- API helpers ---
  window.cancelJob = function (jobId) {
    fetch('/api/jobs/' + jobId + '/cancel', { method: 'POST' });
  };

  // --- Init ---
  function init() {
    connectSSE();
    // periodically clean up old completed jobs
    setInterval(function () {
      var now = Date.now();
      for (var id in STATE.jobs) {
        var j = STATE.jobs[id];
        if ((j.status === 'completed' || j.status === 'failed' || j.status === 'cancelled') &&
          j.completed_at) {
          var age = now - new Date(j.completed_at).getTime();
          if (age > 300000) { // 5 min
            delete STATE.jobs[id];
          }
        }
      }
      renderWidget();
    }, 60000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // --- Utils ---
  function escapeHtml(s) {
    if (!s) return '';
    var div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

})();
