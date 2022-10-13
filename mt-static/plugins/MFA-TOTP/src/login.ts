document
  .querySelector("#use-recovery-code")
  ?.addEventListener("click", (ev) => {
    ev.preventDefault();
    const tokenField = document.querySelector(
      "#mfa-totp-token-field"
    ) as HTMLDivElement;
    tokenField.classList.add("d-none");
    (tokenField.querySelector("input") as HTMLInputElement).disabled = true;

    const recoveryCodeField = document.querySelector(
      "#mfa-totp-recovery-code-field"
    ) as HTMLDivElement;
    recoveryCodeField.classList.remove("d-none");
    (recoveryCodeField.querySelector("input") as HTMLInputElement).disabled =
      false;

      console.log(ev.currentTarget);
    (ev.currentTarget as HTMLAnchorElement).remove();
  });

export {};
