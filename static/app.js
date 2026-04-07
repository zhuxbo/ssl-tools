let eventSource = null;

document.addEventListener('DOMContentLoaded', function() {
    loadRegions();
    document.getElementById('input').addEventListener('keydown', function(e) {
        if (e.key === 'Enter') startDiagnose();
    });

    var params = new URLSearchParams(window.location.search);
    var host = params.get('host');
    if (host) {
        var port = params.get('port');
        document.getElementById('input').value = port && port !== '443' ? host + ':' + port : host;
        startDiagnose();
    }
});

function loadRegions() {
    fetch('/api/regions')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var select = document.getElementById('regionSelect');
            if (!data.regions || data.regions.length <= 1) return;
            select.style.display = '';
            data.regions.forEach(function(region) {
                var opt = document.createElement('option');
                opt.value = region.url;
                opt.textContent = region.name;
                if (region.id === data.current || (!data.current && region.default)) {
                    opt.selected = true;
                }
                select.appendChild(opt);
            });
        })
        .catch(function() {});
}

function switchRegion(url) { window.location.href = url + window.location.search; }

function parseInput(raw) {
    raw = raw.trim();
    if (!raw) return null;
    try {
        if (raw.includes('://')) {
            var u = new URL(raw);
            return { host: u.hostname, port: u.port || '443' };
        }
    } catch (e) {}
    var colonCount = (raw.match(/:/g) || []).length;
    if (colonCount === 1) {
        var parts = raw.split(':');
        return { host: parts[0], port: parts[1] };
    }
    return { host: raw, port: '443' };
}

function formatTarget(host, port) {
    return port === '443' ? host : host + ':' + port;
}

function updateURL(host, port) {
    var params = new URLSearchParams();
    params.set('host', host);
    if (port !== '443') params.set('port', port);
    history.replaceState(null, '', '?' + params.toString());
}

function startDiagnose() {
    var input = document.getElementById('input');
    var btn = document.getElementById('btn');
    var raw = input.value.trim();
    if (!raw) return;
    var target = parseInput(raw);
    if (!target) return;

    input.value = formatTarget(target.host, target.port);
    updateURL(target.host, target.port);

    if (eventSource) { eventSource.close(); eventSource = null; }

    btn.disabled = true;
    btn.textContent = '诊断中...';
    resetResults();
    document.getElementById('results').style.display = 'block';
    document.getElementById('loadingDetails').style.display = 'block';
    document.getElementById('loadingProtocols').style.display = 'block';

    var url = '/api/diagnose?host=' + encodeURIComponent(target.host) + '&port=' + encodeURIComponent(target.port);
    eventSource = new EventSource(url);

    eventSource.addEventListener('overview', function(e) { renderOverview(JSON.parse(e.data)); });
    eventSource.addEventListener('details', function(e) {
        document.getElementById('loadingDetails').style.display = 'none';
        renderDetails(JSON.parse(e.data));
    });
    eventSource.addEventListener('certificate', function(e) { renderCertificate(JSON.parse(e.data)); });
    eventSource.addEventListener('protocols', function(e) {
        document.getElementById('loadingProtocols').style.display = 'none';
        renderProtocols(JSON.parse(e.data));
    });
    eventSource.addEventListener('done', function() {
        finish();
    });
    eventSource.onerror = function() {
        finish();
    };
}

function finish() {
    if (eventSource) { eventSource.close(); eventSource = null; }
    document.getElementById('btn').disabled = false;
    document.getElementById('btn').textContent = '诊断';
    document.getElementById('loadingDetails').style.display = 'none';
    document.getElementById('loadingProtocols').style.display = 'none';
}

function resetResults() {
    ['overview', 'details', 'certificate', 'protocols'].forEach(function(id) {
        document.getElementById(id).style.display = 'none';
    });
    document.getElementById('overviewGrid').innerHTML = '';
    document.getElementById('issuesList').style.display = 'none';
    document.getElementById('issuesList').innerHTML = '';
    document.getElementById('detailsBody').innerHTML = '';
    document.getElementById('certificateBody').innerHTML = '';
    document.getElementById('protocolsBody').innerHTML = '';
}

function renderOverview(data) {
    document.getElementById('overview').style.display = 'block';
    document.getElementById('overviewLatency').textContent = '耗时 ' + data.connection.latency_ms + 'ms';

    var grid = document.getElementById('overviewGrid');
    var connOK = data.connection.status === 'ok';
    var connClass = connOK ? 'status-ok' : 'status-error';
    var connTextMap = {
        ok: '✓ 连接成功', timeout: '✗ 连接超时', refused: '✗ 连接被拒绝',
        dns_error: '✗ DNS 解析失败', reset: '✗ 连接被重置', tls_failed: '✗ TLS 握手失败'
    };
    var connText = connTextMap[data.connection.status] || '✗ 连接失败';

    var certClass = data.cert_status === 'valid' ? 'status-ok' : 'status-error';
    var certStatusMap = {
        valid: '✓ 有效', expired: '✗ 已过期', not_yet_valid: '✗ 尚未生效',
        mismatch: '✗ 域名不匹配', self_signed: '⚠ 自签名', untrusted: '✗ 不受信任',
        chain_incomplete: '✗ 链不完整', no_cert: '✗ 无证书'
    };
    var certText = certStatusMap[data.cert_status] || data.cert_status;

    var validityHtml = '-';
    var validityClass = '';
    if (data.validity) {
        validityClass = data.validity.days_left < 0 ? 'status-error' :
            data.validity.days_left <= 30 ? 'status-warning' : '';
        var daysText = data.validity.days_left < 0
            ? '(已过期 ' + Math.abs(data.validity.days_left) + ' 天)'
            : '(剩余 ' + data.validity.days_left + ' 天)';
        validityHtml = data.validity.not_before + ' ~ ' + data.validity.not_after +
            '<br><span style="font-size:11px;">' + daysText + '</span>';
    }

    grid.innerHTML =
        '<div class="overview-item" id="connCard"><div class="label" id="connLabel">连接状态</div><div class="value ' + connClass + '">' + connText + '</div></div>' +
        '<div class="overview-item"><div class="label">证书状态</div><div class="value ' + certClass + '">' + certText + '</div></div>' +
        '<div class="overview-item"><div class="label">有效期</div><div class="value ' + validityClass + '" style="font-size:12px;">' + validityHtml + '</div></div>';

    if (data.issues && data.issues.length > 0) {
        var issuesList = document.getElementById('issuesList');
        issuesList.style.display = 'block';
        var html = '<div class="issues-box"><div class="issues-title">发现 ' + data.issues.length + ' 个问题</div>';
        data.issues.forEach(function(issue) {
            var titleClass = issue.severity === 'error' ? 'status-error' : 'status-warning';
            html += '<div class="issue-item">' +
                '<div class="issue-title ' + titleClass + '">⚠ ' + escapeHtml(issue.title) + '</div>' +
                '<div class="issue-impact">影响: ' + escapeHtml(issue.impact) + '</div>' +
                '<div class="issue-suggestion">' + escapeHtml(issue.suggestion) + '</div></div>';
        });
        html += '</div>';
        issuesList.innerHTML = html;
    }
}

function renderDetails(data) {
    // 状态码补到概览连接状态 label 括号
    if (data.status_code) {
        var connLabel = document.getElementById('connLabel');
        if (connLabel) {
            connLabel.textContent = '连接状态 (' + data.status_code + ')';
        }
    }

    document.getElementById('details').style.display = 'block';
    var body = document.getElementById('detailsBody');
    var html = '<div class="detail-grid">';
    if (data.ip) html += '<span class="label">IP 地址</span><span>' + escapeHtml(data.ip) + '</span>';
    if (data.server) html += '<span class="label">服务器</span><span>' + escapeHtml(data.server) + '</span>';
    html += '<span class="label">HTTP/2</span><span class="' + (data.http2 ? 'status-ok' : '') + '">' + (data.http2 ? '支持' : '不支持') + '</span>';
    html += '<span class="label">HSTS</span><span class="' + (data.hsts ? 'status-ok' : '') + '">' + (data.hsts ? escapeHtml(data.hsts) : '未设置') + '</span>';
    html += '<span class="label">OCSP Stapling</span><span class="' + (data.ocsp_stapled ? 'status-ok' : '') + '">' + (data.ocsp_stapled ? '支持' : '不支持') + '</span>';
    html += '</div>';

    if (data.status_issue) {
        var titleClass = data.status_issue.severity === 'error' ? 'status-error' : 'status-warning';
        html += '<div class="issues-box" style="margin-top:12px;"><div class="issue-item">' +
            '<div class="issue-title ' + titleClass + '">⚠ ' + escapeHtml(data.status_issue.title) + '</div>' +
            '<div class="issue-impact">影响: ' + escapeHtml(data.status_issue.impact) + '</div>' +
            '<div class="issue-suggestion">' + escapeHtml(data.status_issue.suggestion) + '</div></div></div>';
    }
    body.innerHTML = html;
}

function renderCertificate(data) {
    if (!data.subject) return;
    document.getElementById('certificate').style.display = 'block';
    var body = document.getElementById('certificateBody');

    var certTypeText = data.cert_type || '-';
    if (data.is_wildcard) certTypeText += ' (通配符)';

    var html = '<div class="detail-grid">';
    html += '<span class="label">域名 (CN)</span><span>' + escapeHtml(data.subject) + '</span>';
    html += '<span class="label">SAN</span><span style="word-break:break-all;">' + escapeHtml((data.san || []).join(', ')) + '</span>';
    html += '<span class="label">签发者</span><span>' + escapeHtml(data.issuer) + '</span>';
    if (data.organization) html += '<span class="label">组织机构</span><span>' + escapeHtml(data.organization) + '</span>';
    html += '<span class="label">证书类型</span><span>' + escapeHtml(certTypeText) + '</span>';
    var notBeforeLocal = data.not_before_ts ? formatTS(data.not_before_ts) : data.validity.not_before;
    var notAfterLocal = data.not_after_ts ? formatTS(data.not_after_ts) : data.validity.not_after;
    html += '<span class="label">有效期</span><span' + (data.validity.days_left < 0 ? ' class="status-error"' : '') + '>' +
        notBeforeLocal + ' ~ ' + notAfterLocal + '</span>';
    html += '<span class="label">密钥算法</span><span>' + escapeHtml(data.key.algorithm + ' ' + data.key.size) + '</span>';
    html += '<span class="label">签名算法</span><span>' + escapeHtml(data.signature_algorithm) + '</span>';
    html += '<span class="label">CT (SCT)</span><span class="' + (data.sct_count > 0 ? 'status-ok' : '') + '">' + (data.sct_count > 0 ? '嵌入 ' + data.sct_count + ' 条' : '无') + '</span>';
    if (data.ocsp_servers && data.ocsp_servers.length > 0) {
        html += '<span class="label">OCSP 地址</span><span style="font-size:12px;word-break:break-all;">' + data.ocsp_servers.map(escapeHtml).join('<br>') + '</span>';
    }
    html += '<span class="label">指纹 (SHA-256)</span><span style="font-family:monospace;font-size:11px;word-break:break-all;">' + escapeHtml(data.fingerprint) + '</span>';
    html += '<span class="label">序列号</span><span style="font-family:monospace;font-size:11px;">' + escapeHtml(data.serial_number) + '</span>';
    html += '</div>';

    if (data.chain && data.chain.length > 0) {
        html += '<div class="chain-list"><div style="color:#999;margin-bottom:4px;">服务端证书链:</div>';
        data.chain.forEach(function(cert, i) {
            html += '<div>' + (i + 1) + '. ' + escapeHtml(cert.subject) +
                ' <span style="color:#999;">— ' + escapeHtml(cert.issuer) + '</span></div>';
        });
        html += '</div>';
    }
    body.innerHTML = html;
}

function renderProtocols(data) {
    document.getElementById('protocols').style.display = 'block';
    var body = document.getElementById('protocolsBody');
    var html = '<div style="margin-bottom:12px;font-size:13px;font-weight:500;">支持的协议版本</div><div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">';
    (data.supported || []).forEach(function(p) {
        var cls = p.supported ? 'status-ok' : '';
        var style = 'padding:4px 12px;border-radius:4px;font-size:12px;font-weight:500;';
        if (p.supported && (p.name === 'TLS 1.0' || p.name === 'TLS 1.1')) {
            style += 'background:#fef7f6;color:#d93025;';
        } else if (p.supported) {
            style += 'background:#e6f4ea;color:#1e8e3e;';
        } else {
            style += 'background:#f5f5f5;color:#999;';
        }
        html += '<span style="' + style + '">' + escapeHtml(p.name) + (p.supported ? '' : ' ✗') + '</span>';
    });
    html += '</div>';

    if (data.cipher_suites && data.cipher_suites.length > 0) {
        html += '<div style="font-size:13px;font-weight:500;margin-bottom:4px;">加密套件</div><div style="font-size:12px;line-height:2;">';
        data.cipher_suites.forEach(function(cs) {
            var color = cs.secure ? '#333' : '#d93025';
            html += '<div style="color:' + color + ';">' + escapeHtml(cs.name) +
                ' <span style="color:#999;font-size:11px;">(' + escapeHtml(cs.version) + ')</span>' +
                (cs.secure ? '' : ' ⚠') + '</div>';
        });
        html += '</div>';
    }

    if (data.insecure_items && data.insecure_items.length > 0) {
        html += '<div class="issues-box" style="margin-top:12px;"><div class="issues-title">不安全项</div>';
        data.insecure_items.forEach(function(item) {
            html += '<div class="issue-item"><div class="issue-title status-warning">⚠ ' + escapeHtml(item) + '</div></div>';
        });
        html += '</div>';
    }
    body.innerHTML = html;
}

function toggleCard(id) { document.getElementById(id).classList.toggle('collapsed'); }

function formatTS(ts) {
    var d = new Date(ts * 1000);
    var pad = function(n) { return n < 10 ? '0' + n : n; };
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
        ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
