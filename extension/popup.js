// popup.js — runs when the extension popup is opened.
// Responsible for: reading the active tab's URL, calling our local API,
// and rendering the result.

const API_URL = "https://phishing-detection-ml-xsjo.onrender.com/predict";

const currentUrlEl = document.getElementById("current-url");
const checkBtn = document.getElementById("check-btn");
const resultEl = document.getElementById("result");

let activeTabUrl = null;

// chrome.tabs.query with {active: true, currentWindow: true} gets us the
// URL of whichever tab the user currently has open and focused.
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs.length > 0 && tabs[0].url) {
    activeTabUrl = tabs[0].url;
    currentUrlEl.textContent = activeTabUrl;
  } else {
    currentUrlEl.textContent = "Could not read the current tab's URL.";
    checkBtn.disabled = true;
  }
});

checkBtn.addEventListener("click", async () => {
  if (!activeTabUrl) return;

  // Some URLs (browser internal pages like chrome://extensions) aren't
  // real websites and shouldn't be sent to the model.
  if (!activeTabUrl.startsWith("http://") && !activeTabUrl.startsWith("https://")) {
    showResult("error", "This isn't a regular website — nothing to check here.");
    return;
  }

  checkBtn.disabled = true;
  checkBtn.textContent = "Checking...";
  resultEl.style.display = "none";

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: activeTabUrl }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Server returned ${response.status}`);
    }

    const data = await response.json();
    const confidencePercent = Math.round(data.confidence * 100);

    if (data.prediction === "phishing") {
      showResult("phishing", `⚠️ Likely PHISHING (${confidencePercent}% confidence)`);
    } else {
      showResult("legitimate", `✅ Looks legitimate (${confidencePercent}% confidence)`);
    }
  } catch (err) {
    // Most likely cause during development: the Flask server isn't running.
    showResult("error", `Could not reach the detector. Is the API running? (${err.message})`);
  } finally {
    checkBtn.disabled = false;
    checkBtn.textContent = "Check this site";
  }
});

function showResult(type, message) {
  resultEl.className = type;
  resultEl.textContent = message;
  resultEl.style.display = "block";
}
