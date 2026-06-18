document.getElementById("device-form").addEventListener("submit", async function(e) {
	e.preventDefault();
	var form = this;
	var data = {
		name: form.name.value,
		address: form.address.value,
		transport: form.transport.value,
		key: form.key.value
	};
	var res = await fetch("/api/devices", {
		method: "POST", headers: { "Content-Type": "application/json" },
		body: JSON.stringify(data)
	});
	if (res.ok) window.location.reload();
});

document.getElementById("rule-form").addEventListener("submit", async function(e) {
	e.preventDefault();
	var form = this;
	var data = {
		name: form.name.value,
		direction: form.direction.value,
		protocol: form.protocol.value,
		source: form.source.value,
		destination: form.destination.value,
		action: form.action.value,
		ai_enabled: form.ai_enabled.checked
	};
	var res = await fetch("/api/rules", {
		method: "POST", headers: { "Content-Type": "application/json" },
		body: JSON.stringify(data)
	});
	if (res.ok) window.location.reload();
});

document.getElementById("analyze-btn").addEventListener("click", async function() {
	var data = {
		source: document.getElementById("ana-source").value,
		destination: document.getElementById("ana-dest").value,
		protocol: document.getElementById("ana-proto").value,
		payload: document.getElementById("ana-payload").value
	};
	var res = await fetch("/api/firewall/analyze", {
		method: "POST", headers: { "Content-Type": "application/json" },
		body: JSON.stringify(data)
	});
	var result = await res.json();
	var el = document.getElementById("ana-result");
	el.textContent = JSON.stringify(result, null, 2);
	el.classList.add("visible");
});

fetch("/api/ollama/status").then(function(res) { return res.json(); }).then(function(data) {
	document.getElementById("ollama-status").textContent = data.status || "unknown";
}).catch(function() {
	document.getElementById("ollama-status").textContent = "unavailable";
});
