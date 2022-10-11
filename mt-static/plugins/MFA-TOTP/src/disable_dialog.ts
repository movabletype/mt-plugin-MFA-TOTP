import $ from "jquery";

const form = document.querySelector("form") as HTMLFormElement;

const closeButton = document.querySelector("#close") as HTMLButtonElement;
const deleteButton = document.querySelector("#delete") as HTMLButtonElement;
const totpTokenInput = document.querySelector(
  "#mfa-totp-token"
) as HTMLInputElement;
const magicTokenInput = document.querySelector(
  "#magic-token"
) as HTMLInputElement;

totpTokenInput.addEventListener("input", () => {
  deleteButton.disabled = totpTokenInput.value.length < 6;
});

deleteButton.addEventListener("click", () => {
  document.querySelectorAll(".alert").forEach((el) => el.remove());

  $.ajax({
    type: "POST",
    url: window.ScriptURI,
    data: {
      __mode: "mfa_totp_disable",
      mfa_totp_token: totpTokenInput.value,
      magic_token: magicTokenInput.value,
    },
  }).then(function ({ error }: { error?: string }) {
    if (error) {
      const alert = document.createElement("template");
      alert.innerHTML =
        '<div class="row"><div class="col-12"><div class="alert alert-danger" role="alert"></div></div></div>';
      (alert.content.querySelector(".alert") as HTMLDivElement).textContent =
        error;

      const container = document.querySelector(".modal-body");
      container?.insertBefore(alert.content, container.firstChild);
      return;
    }

    form.classList.add("d-none");
    document.querySelector("#deleted-message")?.classList.remove("d-none");

    deleteButton.disabled = true;
    deleteButton.classList.add("d-none");
    closeButton.focus();
  });
});

form.addEventListener("submit", (ev) => {
  ev.preventDefault();
  if (deleteButton.disabled) {
    return;
  }
  deleteButton.click();
});
