const DEFAULTS = {
	mode: "specific",
	sites: ["gemini.google.com"]
};

const sitesEl = document.getElementById("sites");
const statusEl = document.getElementById("status");

function modeInputs() {
	return Array.from(document.querySelectorAll('input[name="mode"]'));
}

function selectedMode() {
	const checked = modeInputs().find((i) => i.checked);
	return checked ? checked.value : "specific";
}

function syncDisabledState() {
	sitesEl.disabled = selectedMode() === "all";
}

function load() {
	chrome.storage.sync.get(DEFAULTS, (stored) => {
		const mode = stored.mode || "specific";
		const sites = Array.isArray(stored.sites) ? stored.sites : DEFAULTS.sites;
		modeInputs().forEach((i) => { i.checked = i.value === mode; });
		sitesEl.value = sites.join("\n");
		syncDisabledState();
	});
}

function save() {
	const sites = sitesEl.value
		.split("\n")
		.map((s) => s.trim())
		.filter(Boolean);
	chrome.storage.sync.set({ mode: selectedMode(), sites }, () => {
		statusEl.classList.add("show");
		setTimeout(() => statusEl.classList.remove("show"), 1200);
	});
}

modeInputs().forEach((i) => i.addEventListener("change", syncDisabledState));
document.getElementById("save").addEventListener("click", save);
load();
