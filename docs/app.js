// Configure these after deploying to your GitHub repo
var REPO_OWNER = 'elchacal801';
var REPO_NAME = 'threat-intel-reference';
var BRANCH = 'master';

function rawUrl(path) {
    return 'https://raw.githubusercontent.com/' + REPO_OWNER + '/' + REPO_NAME + '/' + BRANCH + '/' + path;
}

var dataCache = {};

function fetchJSON(path) {
    if (dataCache[path]) return Promise.resolve(dataCache[path]);
    return fetch(rawUrl(path))
        .then(function(resp) {
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            return resp.json();
        })
        .then(function(data) {
            dataCache[path] = data;
            return data;
        })
        .catch(function(e) {
            console.error('Failed to fetch ' + path + ':', e);
            return null;
        });
}

function loadStats() { return fetchJSON('data/normalized/stats.json'); }
function loadMalwareSamples() { return fetchJSON('data/normalized/malware_samples.json'); }
function loadPupSamples() { return fetchJSON('data/normalized/pup_pua_samples.json'); }
function loadFamilies() { return fetchJSON('data/normalized/malware_families.json'); }
function loadIOCs() { return fetchJSON('data/normalized/iocs.json'); }

function createBadge(classification) {
    var span = document.createElement('span');
    var cls = (classification || 'malware').toLowerCase();
    span.className = 'badge ' + cls;
    span.textContent = cls;
    return span;
}

function renderTable(containerId, headers, rows, page, pageSize) {
    var container = document.getElementById(containerId);
    if (!container) return;

    var start = (page - 1) * pageSize;
    var pageRows = rows.slice(start, start + pageSize);
    var totalPages = Math.ceil(rows.length / pageSize);

    // Clear container
    while (container.firstChild) container.removeChild(container.firstChild);

    // Result count
    var countP = document.createElement('p');
    countP.style.color = 'var(--text-muted)';
    countP.style.marginBottom = '12px';
    countP.textContent = rows.length.toLocaleString() + ' results';
    container.appendChild(countP);

    // Table
    var table = document.createElement('table');
    var thead = document.createElement('thead');
    var headerRow = document.createElement('tr');
    headers.forEach(function(h) {
        var th = document.createElement('th');
        th.textContent = h.label;
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    var tbody = document.createElement('tbody');
    pageRows.forEach(function(row) {
        var tr = document.createElement('tr');
        headers.forEach(function(h) {
            var td = document.createElement('td');
            var val = row[h.key] || '';
            if (h.key === 'classification') {
                td.appendChild(createBadge(val));
            } else {
                td.textContent = String(val).substring(0, 80);
            }
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    container.appendChild(table);

    // Pagination
    if (totalPages > 1) {
        var pag = document.createElement('div');
        pag.className = 'pagination';

        if (page > 1) {
            var prevBtn = document.createElement('button');
            prevBtn.textContent = 'Prev';
            prevBtn.addEventListener('click', function() { goToPage(page - 1); });
            pag.appendChild(prevBtn);
        }

        var startPage = Math.max(1, page - 2);
        var endPage = Math.min(totalPages, page + 2);
        for (var i = startPage; i <= endPage; i++) {
            var btn = document.createElement('button');
            btn.textContent = i;
            if (i === page) btn.className = 'active';
            btn.dataset.page = i;
            btn.addEventListener('click', function() { goToPage(parseInt(this.dataset.page)); });
            pag.appendChild(btn);
        }

        if (page < totalPages) {
            var nextBtn = document.createElement('button');
            nextBtn.textContent = 'Next';
            nextBtn.addEventListener('click', function() { goToPage(page + 1); });
            pag.appendChild(nextBtn);
        }

        container.appendChild(pag);
    }
}

function downloadCSV(rows, headers, filename) {
    var csv = headers.map(function(h) { return h.label; }).join(',') + '\n';
    rows.forEach(function(row) {
        csv += headers.map(function(h) {
            var val = String(row[h.key] || '').replace(/"/g, '""');
            return '"' + val + '"';
        }).join(',') + '\n';
    });
    var blob = new Blob([csv], { type: 'text/csv' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
}
