import QRCode from "qrcode";
import $ from "jquery";

// render QR Code
document
  .querySelectorAll<HTMLCanvasElement>("canvas[data-totp-uri]")
  .forEach((canvas) => {
    const uri = canvas.dataset.totpUri;
    QRCode.toCanvas(canvas, uri);
  });

// get DOM Elements
const form = document.querySelector("form") as HTMLFormElement;

const continueButton = document.querySelector("#continue") as HTMLButtonElement;
const finishButton = document.querySelector("#finish") as HTMLButtonElement;
const totpTokenInput = document.querySelector(
  "#mfa-totp-token"
) as HTMLInputElement;
const magicTokenInput = document.querySelector(
  "#magic-token"
) as HTMLInputElement;

// prevent unintentional closing of modal windows
const closeModalMessage = form.dataset.mtMfaTotpCloseModalMessage;
document.querySelectorAll("[data-mt-modal-close]").forEach((el) => {
  el.addEventListener("click", (ev) => {
    if (!finishButton.disabled) {
      // completed!
      return;
    }

    ev.preventDefault();
    ev.stopPropagation();
    ev.stopImmediatePropagation();
    if (confirm(closeModalMessage)) {
      window.top?.jQuery.fn.mtModal.close();
    }
  });
});

window.top?.addEventListener("beforeunload", (ev) => {
  if (!finishButton.disabled) {
    // completed!
    return;
  }
  ev.preventDefault();
  ev.returnValue = closeModalMessage;
});

// handle events
totpTokenInput.addEventListener("input", () => {
  continueButton.disabled = totpTokenInput.value.length < 6;
});

continueButton.addEventListener("click", () => {
  document.querySelector(".alert.alert-danger")?.classList.add("d-none");

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
      const alert = document.querySelector(".alert.alert-danger") as HTMLDivElement;
      alert?.classList.remove("d-none");
      (alert.firstChild as HTMLParagraphElement).textContent = error;
      return;
    }

    form.classList.add("d-none");
    (
      document.querySelector("#completed-panel") as HTMLDivElement
    ).classList.remove("d-none");

    const recoveryCodes = result?.recovery_codes || [];
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

form.addEventListener("submit", (ev) => {
  ev.preventDefault();
  if (continueButton.disabled) {
    return;
  }
  continueButton.click();
});
