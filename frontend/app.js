const AUTH_URL = window.AUTH_URL ?? "http://localhost:8000";
const PROTECTED_URL = window.PROTECTED_URL ?? "http://localhost:8001";

const loginForm = document.querySelector("#login-form");
const refreshButton = document.querySelector("#refresh-button");
const logoutButton = document.querySelector("#logout-button");
const secretButton = document.querySelector("#secret-button");
const profileButton = document.querySelector("#profile-button");
const sessionOutput = document.querySelector("#session-output");
const apiOutput = document.querySelector("#api-output");

function showResult(element, data) {
  element.textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
}

async function handleRequest(url, options = {}, target = sessionOutput) {
  try {
    const response = await fetch(url, {
      credentials: "include",
      ...options,
    });
    const data = await response.json().catch(() => ({ detail: response.statusText }));
    if (!response.ok) {
      throw new Error(data.detail || `Request failed with ${response.status}`);
    }
    showResult(target, data);
    return data;
  } catch (error) {
    showResult(target, { error: error.message });
    throw error;
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(loginForm);
  const payload = {
    username: formData.get("username"),
    password: formData.get("password"),
  };
  await handleRequest(`${AUTH_URL}/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
});

refreshButton.addEventListener("click", async () => {
  await handleRequest(
    `${AUTH_URL}/token/refresh`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    },
    sessionOutput,
  );
});

logoutButton.addEventListener("click", async () => {
  await handleRequest(
    `${AUTH_URL}/logout`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    },
    sessionOutput,
  );
  showResult(apiOutput, {});
});

secretButton.addEventListener("click", async () => {
  await handleRequest(`${PROTECTED_URL}/api/secret`, {}, apiOutput);
});

profileButton.addEventListener("click", async () => {
  await handleRequest(`${PROTECTED_URL}/api/profile`, {}, apiOutput);
});
