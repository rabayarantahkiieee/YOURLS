(function () {
    'use strict';

    document.addEventListener('DOMContentLoaded', function () {
        var selectAll = document.getElementById('modern-select-all');
        var toolbar   = document.getElementById('modern-bulk-toolbar');
        var countEl   = document.getElementById('modern-bulk-count');
        var deleteBtn = document.getElementById('modern-bulk-delete');

        if (!toolbar || !deleteBtn) {
            return;
        }

        function checkboxes() {
            return Array.prototype.slice.call(document.querySelectorAll('.modern-bulk-select'));
        }

        function refresh() {
            var checked = checkboxes().filter(function (c) { return c.checked; });
            countEl.textContent = checked.length + ' selected';
            deleteBtn.disabled = checked.length === 0;
        }

        document.addEventListener('change', function (e) {
            if (e.target && e.target.classList && e.target.classList.contains('modern-bulk-select')) {
                refresh();
            }
        });

        if (selectAll) {
            selectAll.addEventListener('change', function () {
                checkboxes().forEach(function (c) { c.checked = selectAll.checked; });
                refresh();
            });
        }

        deleteBtn.addEventListener('click', function () {
            var checked = checkboxes().filter(function (c) { return c.checked; }).map(function (c) { return c.value; });
            if (!checked.length) {
                return;
            }
            if (!window.confirm('Delete ' + checked.length + ' selected link(s)? This cannot be undone.')) {
                return;
            }

            var params = new URLSearchParams();
            params.set('action', 'modern_auth_bulk_delete');
            params.set('nonce', window.modernAuthBulkNonce || '');
            checked.forEach(function (k) { params.append('keywords[]', k); });

            deleteBtn.disabled = true;

            fetch(window.ajaxurl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: params.toString(),
                credentials: 'same-origin'
            })
                .then(function (r) { return r.json(); })
                .then(function (resp) {
                    var failed = (resp && resp.failed) || [];
                    checked.forEach(function (k) {
                        if (failed.indexOf(k) === -1) {
                            var box = document.querySelector('input.modern-bulk-select[value="' + k.replace(/"/g, '\\"') + '"]');
                            var row = box ? box.closest('tr') : null;
                            if (row) {
                                row.parentNode.removeChild(row);
                            }
                        }
                    });
                    if (selectAll) {
                        selectAll.checked = false;
                    }
                    refresh();
                    if (failed.length) {
                        window.alert('Some links could not be deleted (not owned by you?): ' + failed.join(', '));
                    }
                })
                .catch(function () {
                    window.alert('Bulk delete failed. Please try again.');
                })
                .finally(function () {
                    refresh();
                });
        });

        refresh();
    });
})();
