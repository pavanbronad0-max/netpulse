let registering = false;
let csrf = "";
const form = document.querySelector("#auth-form");
const errorBox = document.querySelector("#auth-error");

async function getCsrf() {
  const response = await fetch("/api/auth/csrf");
  csrf = (await response.json()).csrf_token;
}

document.querySelector("#auth-switch").addEventListener("click", () => {
  registering = !registering;
  document.querySelector("#auth-title").textContent = registering ? "Create your account" : "Welcome back";
  document.querySelector("#auth-subtitle").textContent = registering ? "Register a local account for this device." : "Sign in to your NetPulse device.";
  document.querySelector("#auth-submit").textContent = registering ? "Create account" : "Sign in";
  document.querySelector("#auth-switch-text").textContent = registering ? "Already registered?" : "New to this device?";
  document.querySelector("#auth-switch").textContent = registering ? "Sign in" : "Create an account";
  document.querySelector("#password").autocomplete = registering ? "new-password" : "current-password";
  errorBox.classList.add("hidden");
});

form.addEventListener("submit", async event => {
  event.preventDefault();
  errorBox.classList.add("hidden");
  const payload = {
    username: document.querySelector("#username").value,
    password: document.querySelector("#password").value
  };
  try {
    const response = await fetch(`/api/auth/${registering ? "register" : "login"}`, {
      method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Authentication failed.");
    location.assign("/");
  } catch (error) {
    errorBox.textContent = error.message || "Unable to connect to NetPulse.";
    errorBox.classList.remove("hidden");
  }
});

getCsrf().catch(() => {
  errorBox.textContent = "Could not connect to NetPulse. Refresh and try again.";
  errorBox.classList.remove("hidden");
});
