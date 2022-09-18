import QRCode from "qrcode";
import $ from "jquery";

document
  .querySelectorAll<HTMLCanvasElement>("canvas[data-totp-uri]")
  .forEach((canvas) => {
    const uri = canvas.dataset.totpUri;
    QRCode.toCanvas(canvas, uri);
  });

const continueButton = document.querySelector("#continue") as HTMLButtonElement;
const finishButton = document.querySelector("#finish") as HTMLButtonElement;

const token = document.querySelector(
  "#mfa-google-auth-token"
) as HTMLInputElement;
token.addEventListener("input", () => {
  continueButton.disabled = token.value.length !== 6;
});
continueButton.addEventListener("click", () => {
  $(".alert").remove();

  $.ajax({
    type: "POST",
    url: window.ScriptURI + "?__mode=mfa_totp_enable",
    data:
      "mfa_totp_token=" +
      token.value +
      "&magic_token=" +
      $("#magic-token").val(),
  }).then(function (data) {
    if (data.error) {
      const $error = $(
        '<div class="row"><div class="col-12"><div class="alert alert-danger" role="alert"></div></div></div>'
      );
      $error.find(".alert").text(data.error);
      $(".modal-body").prepend($error);
      return;
    }

    const res = data.result;

    $("form").addClass("d-none");
    const $recovery_codes = $("#recovery-codes");
    $recovery_codes.removeClass("d-none");
    $recovery_codes.find("code").text(res.recovery_codes.join("\n"));
    document
      .querySelector("#download-recovery-codes")
      ?.setAttribute(
        "href",
        "data:text/plain;charset=utf-8," +
          encodeURIComponent(res.recovery_codes.join("\n"))
      );

    continueButton.disabled = true;
    continueButton.classList.add("d-none");
    finishButton.disabled = false;
    finishButton.classList.remove("d-none");
  });
});
