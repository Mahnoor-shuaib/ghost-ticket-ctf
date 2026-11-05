// Dashboard helper script.
// Staff notes endpoint (v2 panel). Only admins see the button.
const STAFF_NOTES_ENDPOINT = "/api/admin/notes";

async function init() {
  const btn = document.getElementById("staff-btn");
  const out = document.getElementById("staff-out");
  if (!btn) return;

  const me = await fetch("/api/me").then(r => r.json());
  if (me.role !== "admin") return;   // regular users never see the button

  btn.hidden = false;
  btn.addEventListener("click", async () => {
    const data = await fetch(STAFF_NOTES_ENDPOINT).then(r => r.json());
    out.textContent = data.notes.join("\n");
    out.hidden = false;
  });
}

init();
