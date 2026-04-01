const input = document.getElementById("password");
const bar = document.getElementById("bar");
const strength = document.getElementById("strength");
const entropyText = document.getElementById("entropy");

const online = document.getElementById("online");
const fast = document.getElementById("fast");
const slow = document.getElementById("slow");

const breach = document.getElementById("breach");
const feedback = document.getElementById("feedback");
const toggle = document.getElementById("toggle");

/* Toggle eye */
toggle.addEventListener("click", () => {
    if (input.type === "password") {
        input.type = "text";
        toggle.textContent = "🙈";
    } else {
        input.type = "password";
        toggle.textContent = "👁️";
    }
});

/* SHA1 */
async function sha1(str) {
    const buf = new TextEncoder().encode(str);
    const hash = await crypto.subtle.digest("SHA-1", buf);
    return [...new Uint8Array(hash)]
        .map(b => b.toString(16).padStart(2,'0'))
        .join('')
        .toUpperCase();
}

/* Leak check */
async function checkBreach(password) {
    const hash = await sha1(password);
    const prefix = hash.slice(0,5);
    const suffix = hash.slice(5);

    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    const text = await res.text();

    const found = text.includes(suffix);

    if (found) {
        breach.innerHTML = "⚠️ This password has been exposed in data breaches!";
        breach.className = "breach leaked";
    } else {
        breach.innerHTML = "🔐 Good news! This password was NOT found in known leaks.";
        breach.className = "breach safe";
    }
}

/* Main */
input.addEventListener("input", async () => {
    const pwd = input.value;

    /* RESET */
    if (!pwd) {
        bar.style.width = "0%";
        bar.style.background = "none";

        strength.innerText = "Strength: -";
        entropyText.innerText = "Entropy: -";

        online.innerText = "-";
        fast.innerText = "-";
        slow.innerText = "-";

        breach.innerText = "";
        breach.className = "breach";

        feedback.innerHTML = "";
        return;
    }

    const result = zxcvbn(pwd);

    /* COLOR BAR */
    const colors = [
        "linear-gradient(90deg,#ef4444,#dc2626)",
        "linear-gradient(90deg,#f97316,#ea580c)",
        "linear-gradient(90deg,#eab308,#ca8a04)",
        "linear-gradient(90deg,#22c55e,#16a34a)",
        "linear-gradient(90deg,#4ade80,#22c55e)"
    ];

    bar.style.width = ((result.score + 1) * 20) + "%";
    bar.style.background = colors[result.score];

    /* STRENGTH TEXT */
    const labels = ["Very Weak","Weak","Medium","Strong","Very Strong"];
    strength.innerText = labels[result.score];

    if (result.score <= 2) {
        strength.innerText += " ⚠️ Improve recommended";
    }

    /* ENTROPY */
    const entropy = Math.log2(Math.pow(94, pwd.length)).toFixed(2);
    entropyText.innerText = "Entropy: " + entropy + " bits";

    /* TABLE */
    online.innerText = result.crack_times_display.online_no_throttling_10_per_second;
    fast.innerText = result.crack_times_display.offline_fast_hashing_1e10_per_second;
    slow.innerText = result.crack_times_display.offline_slow_hashing_1e4_per_second;

    /* 🔥 SMART FEEDBACK */
    let fb = [];

    // zxcvbn
    if (result.feedback.warning) fb.push(result.feedback.warning);
    fb = fb.concat(result.feedback.suggestions);

    // custom rules
    if (pwd.length < 10) {
        fb.push("Use at least 10 characters.");
    }

    if (!/[A-Z]/.test(pwd)) {
        fb.push("Add uppercase letters (A-Z).");
    }

    if (!/[a-z]/.test(pwd)) {
        fb.push("Add lowercase letters (a-z).");
    }

    if (!/[0-9]/.test(pwd)) {
        fb.push("Include numbers (0-9).");
    }

    if (!/[!@#$%^&*(),.?\":{}|<>]/.test(pwd)) {
        fb.push("Add special characters (e.g. @, #, $).");
    }

    if (result.score >= 4 && fb.length === 0) {
        fb.push("✅ Excellent password. No recommendations needed.");
    }

    feedback.innerHTML = fb.map(f => `<li>⚠️ ${f}</li>`).join("");

    /* LEAK CHECK */
    checkBreach(pwd);
});