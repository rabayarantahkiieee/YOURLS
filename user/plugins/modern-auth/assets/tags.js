(function () {
    'use strict';

    function closePopup() {
        var existing = document.querySelector('.modern-tags-popup');
        if (existing) {
            existing.remove();
        }
        document.removeEventListener('click', onDocClick, true);
    }

    function onDocClick(e) {
        var popup = document.querySelector('.modern-tags-popup');
        if (popup && !popup.contains(e.target) && !e.target.closest('.modern-tags-edit')) {
            closePopup();
        }
    }

    function showPopup(button, cell) {
        closePopup();

        var popup = document.createElement('div');
        popup.className = 'modern-tags-popup';
        popup.innerHTML =
            '<input type="text" class="modern-tags-popup-input" list="modern-tags-datalist" ' +
            'placeholder="tag1, tag2" value="' + (cell.getAttribute('data-tags') || '').replace(/"/g, '&quot;') + '" />' +
            '<div class="modern-tags-popup-hint">Comma-separated. Reuse an existing tag to keep things findable.</div>' +
            '<div class="modern-tags-popup-actions">' +
            '<button type="button" class="button modern-tags-popup-save">Save</button>' +
            '<button type="button" class="button modern-tags-popup-cancel">Cancel</button>' +
            '</div>';

        document.body.appendChild(popup);

        var rect = button.getBoundingClientRect();
        popup.style.left = Math.max(8, rect.left) + 'px';
        popup.style.top = (rect.bottom + 8) + 'px';

        var input = popup.querySelector('.modern-tags-popup-input');
        input.focus();
        input.select();

        popup.querySelector('.modern-tags-popup-cancel').addEventListener('click', closePopup);

        popup.querySelector('.modern-tags-popup-save').addEventListener('click', function () {
            var keyword = cell.getAttribute('data-keyword');
            var nonce = cell.getAttribute('data-nonce');
            var params = new URLSearchParams();
            params.set('action', 'modern_auth_set_tags');
            params.set('keyword', keyword);
            params.set('nonce', nonce);
            params.set('tags', input.value);

            fetch(window.ajaxurl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: params.toString(),
                credentials: 'same-origin'
            })
                .then(function (r) { return r.json(); })
                .then(function (resp) {
                    if (resp && resp.success) {
                        var wrapper = document.createElement('div');
                        wrapper.innerHTML = resp.html;
                        cell.replaceWith(wrapper.firstElementChild);
                        closePopup();
                    } else {
                        window.alert((resp && resp.message) || 'Could not save tags.');
                    }
                })
                .catch(function () {
                    window.alert('Could not save tags. Please try again.');
                });
        });

        setTimeout(function () {
            document.addEventListener('click', onDocClick, true);
        }, 0);
    }

    function init() {
        document.addEventListener('click', function (e) {
            var button = e.target.closest('.modern-tags-edit');
            if (!button) {
                return;
            }
            var cell = button.closest('.modern-tags-cell');
            if (cell) {
                showPopup(button, cell);
            }
        });

        var tagSelect = document.getElementById('modern-tag-select');
        if (tagSelect) {
            tagSelect.addEventListener('change', function () {
                var url = new URL(window.location.href);
                if (tagSelect.value) {
                    url.searchParams.set('modern_tag', tagSelect.value);
                } else {
                    url.searchParams.delete('modern_tag');
                }
                url.searchParams.delete('page');
                window.location.href = url.toString();
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
