/* Browser-Trust: device fingerprinting and signal collection */

function simpleHash(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) {
        h = Math.imul(31, h) + str.charCodeAt(i) | 0;
    }
    return Math.abs(h).toString(16);
}

function getCanvasFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        canvas.width  = 240;
        canvas.height = 60;
        const ctx = canvas.getContext('2d');

        ctx.fillStyle = '#1a1a2e';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.font = 'bold 16px Arial, sans-serif';
        ctx.fillStyle = '#00ff88';
        ctx.fillText('BrowserTrust-ZTA', 10, 24);

        ctx.font = '11px Courier New, monospace';
        ctx.fillStyle = 'rgba(255,170,0,0.8)';
        ctx.fillText('[!] Never trust, always verify', 10, 44);

        ctx.strokeStyle = '#00ff88';
        ctx.lineWidth = 0.8;
        ctx.beginPath();
        ctx.arc(210, 30, 14, 0, 2 * Math.PI);
        ctx.stroke();

        return simpleHash(canvas.toDataURL());
    } catch (e) {
        return null;
    }
}

function getWebGLInfo() {
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) return null;
        const ext = gl.getExtension('WEBGL_debug_renderer_info');
        if (!ext) return { vendor: 'unknown', renderer: 'unknown' };
        return {
            vendor:   gl.getParameter(ext.UNMASKED_VENDOR_WEBGL),
            renderer: gl.getParameter(ext.UNMASKED_RENDERER_WEBGL),
        };
    } catch (e) {
        return null;
    }
}

function getFontsAvailable() {
    const testFonts = ['Arial', 'Courier New', 'Georgia', 'Times New Roman',
                       'Trebuchet MS', 'Verdana', 'Comic Sans MS'];
    const canvas = document.createElement('canvas');
    const ctx    = canvas.getContext('2d');
    const base   = 'monospace';
    const text   = 'mmmmmmmmmmlli';

    ctx.font = `14px ${base}`;
    const baseW = ctx.measureText(text).width;

    return testFonts.filter(font => {
        ctx.font = `14px '${font}', ${base}`;
        return ctx.measureText(text).width !== baseW;
    });
}

function getAudioContext() {
    try {
        const AudioCtx = window.AudioContext || window.webkitAudioContext;
        if (!AudioCtx) return null;
        const ctx  = new AudioCtx();
        const osc  = ctx.createOscillator();
        const anal = ctx.createAnalyser();
        osc.connect(anal);
        anal.connect(ctx.destination);
        osc.type = 'triangle';
        osc.frequency.value = 10000;
        osc.start(0);
        const buf = new Float32Array(anal.frequencyBinCount);
        anal.getFloatFrequencyData(buf);
        osc.stop(0);
        ctx.close();
        return simpleHash(buf.slice(0, 30).join(','));
    } catch (e) {
        return null;
    }
}

document.addEventListener('DOMContentLoaded', function () {
    const langs = navigator.languages
        ? Array.from(navigator.languages)
        : [navigator.language || navigator.userLanguage || ''];

    const deviceInfo = {
        // Core identity
        user_agent:          navigator.userAgent,
        platform:            navigator.platform  || '',
        language:            langs[0] || '',
        languages:           langs,
        timezone:            Intl.DateTimeFormat().resolvedOptions().timeZone,

        // Screen
        screen_width:        screen.width,
        screen_height:       screen.height,
        color_depth:         screen.colorDepth,
        pixel_ratio:         window.devicePixelRatio || 1,

        // Hardware signals
        hardware_concurrency: navigator.hardwareConcurrency || 0,
        device_memory:        navigator.deviceMemory        || null,

        // Browser features
        cookie_enabled:      navigator.cookieEnabled,
        do_not_track:        navigator.doNotTrack || null,
        plugin_count:        navigator.plugins ? navigator.plugins.length : 0,
        touch_support:       ('ontouchstart' in window) || (navigator.maxTouchPoints > 0),

        // Bot detection signal
        webdriver:           navigator.webdriver || false,

        // Rich fingerprints
        canvas_fingerprint:  getCanvasFingerprint(),
        webgl:               getWebGLInfo(),
        fonts_available:     getFontsAvailable().length,
        audio_fingerprint:   getAudioContext(),

        // Network
        connection_type: navigator.connection
            ? (navigator.connection.effectiveType || null)
            : null,
    };

    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = '<p class="loading">Analysing device trust signals...</p>';

    fetch('/submit-device-info', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(deviceInfo),
    })
    .then(res => {
        if (!res.ok) {
            return res.json().then(err => { throw new Error(err.error || 'Server error'); });
        }
        return res.json();
    })
    .then(data => {
        const v     = (data.verdict || '').toLowerCase();
        const score = Math.min(100, Math.max(0, data.trust_score || 0));

        const mkList = (items, cls, icon) =>
            (items || []).map(f =>
                `<li class="${cls}">${icon} ${escHtml(f)}</li>`
            ).join('');

        const posHtml  = mkList(data.positive_factors, 'pos-item', '&#10003;');
        const riskHtml = mkList(data.risk_factors,     'risk-item', '&#9888;');

        resultDiv.innerHTML = `
            <div class="result-card v-${v}">
                <div class="verdict-label">${data.verdict || 'Unknown'}</div>

                <div class="score-wrap">
                    <span class="score-num">${data.trust_score}</span>
                    <span class="score-denom"> / 100</span>
                    <div class="score-bar">
                        <div class="score-fill fill-${v}" style="width:${score}%"></div>
                    </div>
                </div>

                ${posHtml ? `
                <div class="factor-block">
                    <div class="factor-title">Positive Signals</div>
                    <ul>${posHtml}</ul>
                </div>` : ''}

                ${riskHtml ? `
                <div class="factor-block">
                    <div class="factor-title">Risk Factors</div>
                    <ul>${riskHtml}</ul>
                </div>` : ''}
            </div>
        `;
    })
    .catch(err => {
        resultDiv.innerHTML =
            `<div class="error-box">Assessment failed: ${escHtml(err.message)}</div>`;
    });
});

function escHtml(str) {
    return String(str)
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;');
}
