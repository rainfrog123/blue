(() => {
  const statusEl = document.getElementById("status");
  const titleEl = document.getElementById("status-title");
  const detailEl = document.getElementById("status-detail");

  const setStatus = (tone, title, detail) => {
    statusEl.dataset.tone = tone;
    titleEl.textContent = title;
    detailEl.textContent = detail || "";
  };

  const stakeQuery = { url: ["*://*.stake.com/*", "*://stake.com/*"] };

  const refresh = async () => {
    try {
      const st = await chrome.runtime.sendMessage({ type: "popupStatus" });
      const tabs = await chrome.tabs.query(stakeQuery);
      if (!st?.ok) throw new Error("sw");
      if (tabs.length && st.attached > 0) {
        setStatus("ok", "HUD live", st.attached + " debugger target" + (st.attached === 1 ? "" : "s"));
      } else if (tabs.length) {
        setStatus("warn", "Stake open", "Open Multiplay so the HUD can attach");
      } else {
        setStatus("off", "No Stake tab", "Open Stake, then Multiplay");
      }
    } catch (_) {
      setStatus("off", "Extension idle", "Open Stake Multiplay");
    }
  };

  document.getElementById("open").addEventListener("click", async () => {
    const tabs = await chrome.tabs.query(stakeQuery);
    if (tabs[0]) {
      await chrome.tabs.update(tabs[0].id, { active: true });
      if (tabs[0].windowId != null) await chrome.windows.update(tabs[0].windowId, { focused: true });
    } else {
      await chrome.tabs.create({ url: "https://stake.com" });
    }
    window.close();
  });

  document.getElementById("reload").addEventListener("click", async () => {
    const tabs = await chrome.tabs.query(stakeQuery);
    if (tabs[0]?.id != null) await chrome.tabs.reload(tabs[0].id);
    window.close();
  });

  void refresh();
})();
