const form = document.querySelector("#assessment-form");
const output = document.querySelector("#output");
const configButton = document.querySelector("#config-button");
const sendOtpButton = document.querySelector("#send-otp");
const verifyOtpButton = document.querySelector("#verify-otp");
const otpInput = document.querySelector("#otp");
let verificationToken = "";

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearErrors();
  await request("/api/submit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ...Object.fromEntries(new FormData(form).entries()),
      verificationToken
    })
  });
});

sendOtpButton.addEventListener("click", async () => {
  clearErrors();
  verificationToken = "";
  await request("/api/send-otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(Object.fromEntries(new FormData(form).entries()))
  });
});

verifyOtpButton.addEventListener("click", async () => {
  clearErrors();
  const response = await request("/api/verify-otp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: new FormData(form).get("email"),
      otp: otpInput.value
    })
  });
  if (response?.verificationToken) verificationToken = response.verificationToken;
});

configButton.addEventListener("click", async () => {
  clearErrors();
  await request("/api/config-status");
});

async function request(url, options) {
  const submitButton = form.querySelector("button");
  submitButton.disabled = true;
  configButton.disabled = true;
  sendOtpButton.disabled = true;
  verifyOtpButton.disabled = true;
  output.textContent = "Working...";

  try {
    const response = await fetch(url, options);
    const body = await response.json();

    if (!response.ok && body.fields) {
      showErrors(body.fields);
    }

    output.textContent = JSON.stringify(body, null, 2);
    return body;
  } catch (error) {
    output.textContent = error.message;
    return null;
  } finally {
    submitButton.disabled = false;
    configButton.disabled = false;
    sendOtpButton.disabled = false;
    verifyOtpButton.disabled = false;
  }
}

function showErrors(fields) {
  Object.entries(fields).forEach(([field, message]) => {
    const target = document.querySelector(`[data-error="${field}"]`);
    if (target) target.textContent = message;
  });
}

function clearErrors() {
  document.querySelectorAll("[data-error]").forEach((node) => {
    node.textContent = "";
  });
}
