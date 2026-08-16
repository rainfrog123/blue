// Default configuration. mode "all" => isolate zoom on every site.
// mode "specific" => only isolate on the listed sites.
const DEFAULT_CONFIG = {
	mode: "specific",
	sites: ["gemini.google.com"]
};

let config = DEFAULT_CONFIG;

function loadConfig() {
	chrome.storage.sync.get(DEFAULT_CONFIG, (stored) => {
		config = {
			mode: stored.mode || "specific",
			sites: Array.isArray(stored.sites) ? stored.sites : DEFAULT_CONFIG.sites
		};
	});
}

loadConfig();

// Keep the in-memory config fresh when the user saves new settings.
chrome.storage.onChanged.addListener((changes, area) => {
	if (area === "sync" && (changes.mode || changes.sites)) {
		loadConfig();
	}
});

// Normalize a user-entered pattern into a bare host, e.g.
// "https://example.com/*" -> "example.com", "*.foo.com" -> "*.foo.com".
function normalizePattern(pattern) {
	let p = String(pattern).trim().toLowerCase();
	if (!p) return "";
	p = p.replace(/^https?:\/\//, "");
	p = p.replace(/\/.*$/, "");
	return p;
}

function hostMatches(hostname, pattern) {
	const p = normalizePattern(pattern);
	if (!p) return false;
	if (p.startsWith("*.")) {
		const base = p.slice(2);
		return hostname === base || hostname.endsWith("." + base);
	}
	return hostname === p || hostname.endsWith("." + p);
}

function shouldIsolate(url) {
	let hostname;
	try {
		hostname = new URL(url).hostname.toLowerCase();
	} catch (e) {
		return false;
	}
	if (config.mode === "all") return true;
	return config.sites.some((pattern) => hostMatches(hostname, pattern));
}

chrome.tabs.onZoomChange.addListener((zoomChangeInfo) => {
	chrome.tabs.get(zoomChangeInfo.tabId, (tab) => {
		if (chrome.runtime.lastError || !tab || !tab.url) {
			return;
		}
		if (shouldIsolate(tab.url)) {
			chrome.tabs.setZoomSettings(zoomChangeInfo.tabId, { scope: "per-tab" });
		}
	});
});
