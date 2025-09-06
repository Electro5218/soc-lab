var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
// rules.ts
const checkboxes = document.querySelectorAll('.toggle-rule');
checkboxes.forEach(cb => {
    cb.addEventListener('change', () => __awaiter(this, void 0, void 0, function* () {
        const rule = cb.dataset.rule;
        if (!rule)
            return;
        const enabled = cb.checked;
        const row = cb.closest('tr');
        const statusLabel = row === null || row === void 0 ? void 0 : row.querySelector('.status-label');
        try {
            const response = yield fetch('/update_rule', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rule, enabled })
            });
            const data = yield response.json();
            if (data.success) {
                if (statusLabel) {
                    statusLabel.textContent = enabled ? 'Enabled' : 'Disabled';
                    statusLabel.className = 'status-label px-2 inline-flex text-xs leading-5 font-semibold rounded-full ' +
                        (enabled ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800');
                }
            }
            else {
                alert('Failed to change the rule!');
                cb.checked = !enabled;
            }
        }
        catch (err) {
            console.error(err);
            alert('Server error connection!');
            cb.checked = !enabled;
        }
    }));
});
