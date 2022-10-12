import $ from "jquery";
import { showAlert } from "./util";

const noRecoveryCodesContainer = document.querySelector(
  "#no-recovery-codes"
) as HTMLPreElement;
const recoveryCodesContainer = document.querySelector(
  "#recovery-codes"
) as HTMLPreElement;
const generateButton = document.querySelector("#generate") as HTMLButtonElement;
const magicTokenInput = document.querySelector(
  "#magic-token"
) as HTMLInputElement;

function renderRecoveryCodes(recoveryCodes: string[]) {
  if (recoveryCodes.length === 0) {
    noRecoveryCodesContainer.classList.remove("d-none");
    recoveryCodesContainer.classList.add("d-none");
  } else {
    noRecoveryCodesContainer.classList.add("d-none");
    recoveryCodesContainer.classList.remove("d-none");
    (recoveryCodesContainer.querySelector("span") as HTMLElement).textContent = String(recoveryCodes.length);
    (recoveryCodesContainer.querySelector("code") as HTMLElement).textContent =
      recoveryCodes.join("\n");
    document
      .querySelector("#download-recovery-codes")
      ?.setAttribute(
        "href",
        "data:text/plain;charset=utf-8," +
          encodeURIComponent(recoveryCodes.join("\n"))
      );
  }
}

renderRecoveryCodes(
  JSON.parse(recoveryCodesContainer.dataset.mtMfaTotpRecoveryCodes || "[]")
);

generateButton.addEventListener("click", (ev) => {
  document.querySelectorAll(".alert").forEach((el) => el.remove());

  ev.preventDefault();

  if (!window.confirm(generateButton.dataset.mtMfaTotpConfirm)) {
    return;
  }

  $.ajax({
    type: "POST",
    url: window.ScriptURI,
    data: {
      __mode: "mfa_totp_generate_recovery_codes",
      magic_token: magicTokenInput.value,
    },
  }).then(function ({
    error,
    result,
  }: {
    error?: string;
    result?: { recovery_codes: string[] };
  }) {
    if (error) {
      showAlert(error, "danger");
      return;
    }

    showAlert(generateButton.dataset.mtMfaTotpSuccess || "", "success");
    renderRecoveryCodes(result?.recovery_codes || []);
  });
});
