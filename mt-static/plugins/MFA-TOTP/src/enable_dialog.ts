import QRCode from "qrcode";
import $ from "jquery";

document
  .querySelectorAll<HTMLCanvasElement>("canvas[data-totp-uri]")
  .forEach((canvas) => {
    const uri = canvas.dataset.totpUri;
    QRCode.toCanvas(canvas, uri);
  });

const form = document.querySelector("form") as HTMLFormElement;

const continueButton = document.querySelector("#continue") as HTMLButtonElement;
const finishButton = document.querySelector("#finish") as HTMLButtonElement;
const totpTokenInput = document.querySelector(
  "#mfa-totp-token"
) as HTMLInputElement;
const magicTokenInput = document.querySelector(
  "#magic-token"
) as HTMLInputElement;

totpTokenInput.addEventListener("input", () => {
  continueButton.disabled = totpTokenInput.value.length < 6;
});

continueButton.addEventListener("click", () => {
  document.querySelectorAll(".alert").forEach((el) => el.remove());

  $.ajax({
    type: "POST",
    url: window.ScriptURI,
    data: {
      __mode: "mfa_totp_enable",
      mfa_totp_token: totpTokenInput.value,
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
      const alert = document.createElement("template");
      alert.innerHTML =
        '<div class="row"><div class="col-12"><div class="alert alert-danger" role="alert"></div></div></div>';
      (alert.content.querySelector(".alert") as HTMLDivElement).textContent =
        error;

      const container = document.querySelector(".modal-body");
      container?.insertBefore(alert.content, container.firstChild);
      return;
    }

    const recoveryCodes = result?.recovery_codes || [];

    form.classList.add("d-none");

    if (recoveryCodes.length !== 0) {
      const recoveryCodesContainer = document.querySelector(
        "#recovery-codes"
      ) as HTMLDivElement;
      recoveryCodesContainer.classList.remove("d-none");
      (
        recoveryCodesContainer.querySelector("code") as HTMLElement
      ).textContent = recoveryCodes.join("\n");
      document
        .querySelector("#download-recovery-codes")
        ?.setAttribute(
          "href",
          "data:text/plain;charset=utf-8," +
            encodeURIComponent(recoveryCodes.join("\n"))
        );
    }

    continueButton.disabled = true;
    continueButton.classList.add("d-none");
    finishButton.disabled = false;
    finishButton.classList.remove("d-none");
  });
});
