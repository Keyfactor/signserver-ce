/*
 * Table sorting
 */

const TABLE_SORTER_CLASSNAMES = {
    TABLE_SORTER: 'exp-tablesorter',
    SORT_ASC: 'exp-tablesorterAsc',
    SORT_DESC: 'exp-tablesorterDesc',
    SORT_COLUMN: 'exp-tablesorterColumn'
};


function sortTable(table, columnIndex, asc) {
    // select all rows in table then filter out any rows that have a different parent table (i.e. nested tables)
    const rows = Array.from(table.querySelectorAll('tr:not(:has(th, .confluenceTh))'))
        .filter((row) => (row.closest('table') === table));

    rows.sort((a, b) => {
        const cellA = a.cells[columnIndex];
        const cellB = b.cells[columnIndex];

        if (!cellA) {
            return 1;
        }
        if (!cellB) {
            return -1;
        }

        const comparisonValueA = cellA.textContent;
        const comparisonValueB = cellB.textContent;

        // compare strings, also allow numeric comparison method if input is all numeric
        const compared = comparisonValueA.localeCompare(comparisonValueB, undefined, { numeric: true });

        return asc ? compared : -compared;
    });

    rows.forEach((row) => row.parentElement.appendChild(row))
}


function addTableSorting() {
    // one listener for any table
    document.addEventListener('click', (ev) => {
        const clickTarget = ev.target;
        const tableSorterThSelector = `.${TABLE_SORTER_CLASSNAMES.TABLE_SORTER}`;
        if (clickTarget.matches(`${tableSorterThSelector} th, ${tableSorterThSelector} th *,`
            + `${tableSorterThSelector} .confluenceTh, ${tableSorterThSelector} .confluenceTh *`)) {
            const table = clickTarget.closest('table');
            const sortAsc = !table.classList.contains(TABLE_SORTER_CLASSNAMES.SORT_ASC);
            const columnIndex = Array.from(clickTarget.parentElement.children || []).indexOf(clickTarget);

            // remove old sort column indicator
            const oldSortColumn = table.querySelector(`.${TABLE_SORTER_CLASSNAMES.SORT_COLUMN}`);
            if (oldSortColumn && oldSortColumn !== clickTarget) {
                oldSortColumn.classList.remove(TABLE_SORTER_CLASSNAMES.SORT_COLUMN);
            }
            clickTarget.closest('th').classList.add(TABLE_SORTER_CLASSNAMES.SORT_COLUMN);

            // add class to table to mark it as sorted ASC/DESC
            if (sortAsc) {
                table.classList.add(TABLE_SORTER_CLASSNAMES.SORT_ASC);
                table.classList.remove(TABLE_SORTER_CLASSNAMES.SORT_DESC);
            } else {
                table.classList.remove(TABLE_SORTER_CLASSNAMES.SORT_ASC);
                table.classList.add(TABLE_SORTER_CLASSNAMES.SORT_DESC);
            }

            sortTable(table, columnIndex, sortAsc);
        }
    }, false);

    document.querySelectorAll('table')
        .forEach((table) => {
            // mark as using tablesorter
            table.classList.add(TABLE_SORTER_CLASSNAMES.TABLE_SORTER);

        });
}

document.addEventListener('DOMContentLoaded', () => addTableSorting(), false);


/*
 * Lightbox for table and images
 */

// do not add lightbox feature to certain elements like emojis or macro icons
const LIGHTBOX_IGNORE_ELEMENTS = '.emoticon, .icon';

// do not show lightbox when clicking the element, only when the button is clicked
const LIGHTBOX_IGNORE_ELEMENT_CLICKS = 'a img';

const lightboxContainer = document.querySelector('.exp-lightbox-container');

function addLightboxWrapper(el) {
    if (!el.matches(LIGHTBOX_IGNORE_ELEMENTS)) {
        const wrapper = document.querySelector('template#exp-lightbox-wrapper-template')
            .content
            .cloneNode(true)
            .children[0];

        // for tables the wrapper needs to stay block so tables keep full width
        // but for images it can be inline (indicated by the presence of a parent block element)
        if (!el.matches('table') && el.closest('p, blockquote, ol, ul')) {
            wrapper.classList.add('inline');
        }

        el.parentNode.insertBefore(wrapper, el);
        wrapper.appendChild(el);
    }
}

function showInLightbox(element) {
    if (element && lightboxContainer) {
        const copyOfElement = element.cloneNode(true);

        const lightboxContentWrapper = lightboxContainer.querySelector('.lightbox-content');
        lightboxContentWrapper.replaceChildren(copyOfElement);

        if (copyOfElement.matches('img')) {
            copyOfElement.removeAttribute('width');
            copyOfElement.removeAttribute('height');

            lightboxContentWrapper.classList.add('inline');
        }

        if (element.matches('.inline')) {
            lightboxContentWrapper.classList.add('inline');
        }

        lightboxContainer.showModal();
    }
}

function closeLightbox() {
    lightboxContainer.close();
}

function addLightboxModal() {
    document.querySelectorAll('table, img')
        .forEach(addLightboxWrapper);

    document.addEventListener('click', (ev) => {
        const clickTarget = ev.target;
        // toggle when clicking the button or for images, when the image is clicked
        if (clickTarget.matches('.exp-lightbox-toggle, .exp-lightbox-toggle *, .exp-lightbox-wrapper img')
            && !clickTarget.matches(LIGHTBOX_IGNORE_ELEMENT_CLICKS)) {
            ev.preventDefault();
            const wrappedElement = clickTarget.closest('.exp-lightbox-wrapper')
                .querySelector('img, table');

            showInLightbox(wrappedElement);
        } else if (clickTarget.matches('.exp-lightbox-close, .exp-lightbox-close *')) {
            closeLightbox();
        }
    }, false);
}

document.addEventListener('DOMContentLoaded', () => addLightboxModal(), false);


// hide scroll to top button for the first X pixels of scrolling
let SCROLL_TO_TOP_VISIBLE_THRESHOLD = 400;

function scrollListener() {
    const scrollPosition = window.scrollY;
    const scrollButton = document.querySelector('.exp-scroll-to-top-container');

    if (scrollButton) {
        if (scrollPosition > SCROLL_TO_TOP_VISIBLE_THRESHOLD) {
            scrollButton.classList.add('visible');
        } else {
            scrollButton.classList.remove('visible');
        }
    }
}

document.addEventListener('wheel', scrollListener, { passive: true });

document.addEventListener('click', (ev) => {
    // Expand macros
    const clickTarget = ev.target;
    if (clickTarget.matches('.expand-control-text,  .expand-control-text *')) {
        const parentExpand = clickTarget.closest('.expand-container');
        if (parentExpand) {
            parentExpand.classList.toggle('expanded');
        }
    }
}, false);

// save and restore the TOC sidebar scrolling position so users don't lose their position in the sidebar when navigating to other pages
const tocScrollWrapper = document.querySelector('.exp-sidebar-navigation-sticky-wrapper');
if (tocScrollWrapper) {
    // if the user opens a different export in the same session (without closing the tab) it would restore
    // the scroll position from a different export, so we prefix the sessionStorage key by the path of the export file
    const path = window.location.pathname.split('/');
    path.pop();
    const storageKey = 'scrollPosition_' + path.join('/');

    function saveScrollPosition() {
        sessionStorage.setItem(storageKey, tocScrollWrapper.scrollTop);
    }

    function restoreScrollPosition() {
        // TOC - Scroll position persistence logic
        const tocHeight = sessionStorage[storageKey];
        if (tocHeight) {
            tocScrollWrapper.scrollTop = parseInt(tocHeight, 10);
        }
    }

    //Event handler for scroll in toc to store the position
    tocScrollWrapper.addEventListener('scroll', saveScrollPosition, { passive: true });

    document.addEventListener('DOMContentLoaded', () => window.iFrameResize({
        log: false,
        autoResize: true,
        heightCalculationMethod: 'lowestElement',
        checkOrigin: false,
        onInit: restoreScrollPosition
    }, '.exp-sidebar-navigation-sticky-wrapper iframe'), false);
}
