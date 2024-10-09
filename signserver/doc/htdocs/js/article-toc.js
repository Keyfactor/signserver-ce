// sets up the right-side TOC from headings on the page via tocbot
// for the left-side navigation see toc.vm

let headerElement;
const defaultHeightInPixels = 74;
const getHeaderHeight = () => {
    if (!headerElement) {
        headerElement = document.querySelector('header.header');
    }

    if (headerElement) {
        return headerElement.getBoundingClientRect().height;
    }


    return defaultHeightInPixels;
};

const tocPanel = document.querySelector('.js-tocBot');
const tocList = document.querySelector('.toc-list');

if (tocPanel) {
    const tocLinkClass = 'toc-link';
    const tocLinkClassSelector = `.${tocLinkClass}`;

    // Docs for the docbot library can be found here: https://tscanlin.github.io/tocbot/#examples
    // Refer to the documentation there if you want to extend the toc in the theme.
    tocbot.init({
        // Where to render the table of contents.
        tocSelector: '.js-tocBot',
        // Where to grab the headings to build the table of contents.
        contentSelector: '.js-tocBot-content',
        // Main class to add to links
        linkClass: tocLinkClass,
        // Class to add to active links,
        // the link corresponding to the top most heading on the page.
        activeLinkClass: 'toc-link-active',
        // Which headings to grab inside of the contentSelector element.
        headingSelector: 'h1, h2, h3, h4',
        // Smooth scrolling enabled.
        scrollSmooth: true,
        // Smooth scroll duration.
        scrollSmoothDuration: 500,
        // Headings offset between the headings and the top of the document (this is meant for minor adjustments).
        headingsOffset: getHeaderHeight() + 32,
        scrollSmoothOffset: -getHeaderHeight() - 32,
        // How many heading levels should not be collapsed.
        // For example, number 6 will show everything since
        // there are only 6 heading levels and number 0 will collapse them all.
        // The sections that are hidden will open
        // and close as you scroll to headings within them.
        collapseDepth: 6,
        disableTocScrollSync: true
    });

    if (tocList) {
        tocPanel.style.marginBottom = '3em';
    }
}