import $ from "jquery";
import { showAlert } from "./util";

const form = document.querySelector("form") as HTMLFormElement;

const cancelButton = document.querySelector("#cancel") as HTMLElement;
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
      showAlert(error, "danger");
      const alert = document.createElement("template");
      return;
    }

    form.classList.add("d-none");
    document.querySelector("#deleted-message")?.classList.remove("d-none");

    deleteButton.disabled = true;
    deleteButton.classList.add("d-none");
    cancelButton.classList.add("d-none");

    closeButton.classList.remove("d-none");
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
