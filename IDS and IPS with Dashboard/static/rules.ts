// rules.ts
const checkboxes = document.querySelectorAll<HTMLInputElement>('.toggle-rule');

checkboxes.forEach(cb => {
  cb.addEventListener('change', async () => {
    const rule = cb.dataset.rule;
    if (!rule) return;

    const enabled = cb.checked;
    const row = cb.closest('tr');
    const statusLabel = row?.querySelector<HTMLSpanElement>('.status-label');

    try {
      const response = await fetch('/update_rule', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule, enabled })
      });

      const data: { success: boolean } = await response.json();

      if (data.success) {
        if (statusLabel) {
          statusLabel.textContent = enabled ? 'Enabled' : 'Disabled';
          statusLabel.className = 'status-label px-2 inline-flex text-xs leading-5 font-semibold rounded-full ' +
                                  (enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800');
        }
      } else {
        alert('Failed to change the rule!');
        cb.checked = !enabled;
      }
    } catch (err) {
      console.error(err);
      alert('Server error connection!');
      cb.checked = !enabled;
    }
  });
});
