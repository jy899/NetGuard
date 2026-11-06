import { api, session } from "../api.js";
import { logoSvg } from "../device-types.js";
import { readForm, showFormError, withBusy } from "../ui.js";

document.getElementById("login-logo").innerHTML = logoSvg(48);

function nextUrl() {
  const next = new URLSearchParams(window.location.search).get("next");
  // Only allow same-site relative paths to avoid open redirects.
  return next && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/login") ? next : "/dashboard";
}

async function checkExistingSession() {
  if (!session.token) return;
  try {
    await api.get("/auth/me");
    window.location.replace(nextUrl());
  } catch {
    session.clear();
  }
}

const form = document.getElementById("login-form");
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  showFormError(form, "");
  const { username } = readForm(form);
  const password = form.password.value;
  if (!username || !password) {
    showFormError(form, "Enter your username and password.");
    return;
  }
  await withBusy(document.getElementById("login-submit"), async () => {
    try {
      const result = await api.post("/auth/login", { username, password });
      session.save(result.access_token, result.user);
      window.location.replace(nextUrl());
    } catch (error) {
      showFormError(form, error.message);
      form.password.select();
    }
  });
});

checkExistingSession();
