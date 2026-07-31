(function () {
    'use strict';

    function init() {
        var search = document.getElementById('modern-city-search');
        var countrySel = document.getElementById('modern-city-country');
        var table = document.getElementById('modern-city-table');
        if (!table) {
            return;
        }
        var rows = Array.prototype.slice.call(table.querySelectorAll('tbody tr'));

        function apply() {
            var q = ((search && search.value) || '').toLowerCase();
            var country = countrySel ? countrySel.value : '';
            rows.forEach(function (row) {
                var text = row.textContent.toLowerCase();
                var matchesText = !q || text.indexOf(q) !== -1;
                var matchesCountry = !country || row.getAttribute('data-country') === country;
                row.style.display = (matchesText && matchesCountry) ? '' : 'none';
            });
        }

        if (search) {
            search.addEventListener('input', apply);
        }
        if (countrySel) {
            countrySel.addEventListener('change', apply);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
