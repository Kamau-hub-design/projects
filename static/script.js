async function apiRequest(url, method = "GET", data = null) {
    const options = {
        method,
        headers: {
            "Content-Type": "application/json"
        }
    };

    if (data !== null) {
        options.body = JSON.stringify(data);
    }

    const response = await fetch(url, options);
    const result = await response.json();

    if (!response.ok) {
        throw new Error(result.error || result.message || "Request failed");
    }

    return result;
}

async function controlLight(action) {
    try {
        const result = await apiRequest(`/api/${encodeURIComponent(action)}`, "POST");
        updateDisplay(result);
    } catch (error) {
        alert(error.message);
    }
}

function showBrightness(value) {
    document.getElementById("brightnessValue").textContent = value;
}

async function updateBrightness() {
    const brightness = Number(document.getElementById("brightness").value);

    try {
        const result = await apiRequest("/api/brightness", "POST", { brightness });
        updateDisplay(result);
    } catch (error) {
        alert(error.message);
    }
}

function updateDisplay(data) {
    document.getElementById("lightStatus").textContent =
        data.is_on ? "Light is on" : "Light is off";
    document.getElementById("light-icon").textContent = data.is_on ? "💡" : "🌑";

    const brightness = document.getElementById("brightness");
    brightness.value = data.brightness;
    document.getElementById("brightnessValue").textContent = data.brightness;

    document.getElementById("motionStatus").textContent =
        data.motion ? "Movement detected" : "No movement detected";
    document.getElementById("motion").textContent =
        data.motion ? "Detected" : "Not detected";
    document.getElementById("mode").textContent = data.mode;
}

async function refreshStatus() {
    try {
        const result = await apiRequest("/api/status");
        updateDisplay(result);
        document.getElementById("connection").textContent = "Connected";
    } catch (error) {
        document.getElementById("connection").textContent = "Disconnected";
    }
}

async function createSchedule() {
    const action = document.getElementById("action").value;
    const time = document.getElementById("scheduleTime").value;

    if (!time) {
        alert("Please select a date and time");
        return;
    }

    try {
        const result = await apiRequest("/api/schedule", "POST", { action, time });
        document.getElementById("scheduleMessage").textContent = result.message;
    } catch (error) {
        alert(error.message);
    }
}

async function cancelSchedule() {
    try {
        const result = await apiRequest("/api/schedule/cancel", "POST");
        document.getElementById("scheduleMessage").textContent = result.message;
    } catch (error) {
        alert(error.message);
    }
}

refreshStatus();
setInterval(refreshStatus, 3000);
