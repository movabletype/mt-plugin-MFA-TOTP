import $ from "jquery";

const deleteButton = document.querySelector("#delete") as HTMLButtonElement;

const token = document.querySelector(
  "#mfa-google-auth-token"
) as HTMLInputElement;
token.addEventListener("input", () => {
  deleteButton.disabled = token.value.length < 6;
});
deleteButton.addEventListener("click", () => {
  $(".alert").remove();

  $.ajax({
    type: "POST",
    url: window.ScriptURI + "?__mode=mfa_totp_disable",
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

    $("form").addClass("d-none");
    const $deleted_message = $("#deleted-message");
    $deleted_message.removeClass("d-none");

    deleteButton.disabled = true;
    deleteButton.classList.add("d-none");
  });
});
