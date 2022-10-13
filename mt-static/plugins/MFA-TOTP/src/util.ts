const alertTemplate = document.createElement("template");
alertTemplate.innerHTML =
  '<div class="row"><div class="col-12"><div class="alert" role="alert"></div></div></div>';

export function showAlert(message: string, type: "danger" | "success"): void {
  const el = alertTemplate.content.cloneNode(true) as HTMLElement;
  const alert = el.querySelector(".alert") as HTMLDivElement;
  alert.textContent = message;
  alert.classList.add(`alert-${type}`);

  const container = document.querySelector(".modal-body");
  container?.insertBefore(el, container.firstChild);

  window.top?.jQuery(".mt-modal").trigger("resize");
}
