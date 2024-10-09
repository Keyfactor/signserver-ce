document.addEventListener("DOMContentLoaded", function() {
    // sets up the search webworker if search was enabled and connects it to DOM on the page
    // for the worker code see scroll-search.vm

    const searchWorkerTemplate = document.querySelector('#search-worker');
    const searchInputField = document.querySelector('#search-textbox');
    const searchSuggestionResults = document.querySelector('#search-suggestion-container');

    if (searchWorkerTemplate && searchInputField && searchSuggestionResults) {

        function hideSearchSuggestions() {
            searchSuggestionResults.classList.add('hidden');
        }

        function showSearchSuggestions() {
            searchSuggestionResults.classList.remove('hidden');
        }

        function addResultsPageEntry() {
            let href = "search.html?searchQuery=" + encodeURIComponent(searchInputField.value);
            let searchResultsItem = document.createElement('div');
            searchResultsItem.id = "see-all-results"
            searchResultsItem.className = "exp-search-suggestion-option-container search-form-suggestion";
            searchResultsItem.tabIndex = -1;
            let searchResultsLink = document.createElement('a');
            searchResultsLink.href = href;
            searchResultsLink.className = "exp-search-suggestion-option search-form-suggestion search-suggestions-see-all-item";
            searchResultsLink.text = "See all search results";
            searchResultsItem.append(searchResultsLink);
            searchSuggestionResults.append(searchResultsItem);
        }

        function populateSearchSuggestions(results) {
            // map search results to DOM elements with links to the pages
            const searchSuggestionTemplate = document.querySelector('#exp-search-suggestion-option-template');
            const searchSuggestionLinks = results.slice(0, 3).map((result) => {
                const resultItem = searchSuggestionTemplate.content.cloneNode(true);
                const resultLink = resultItem.querySelector('a');
                resultLink.textContent = result.title;
                resultLink.href = result.link;
                return resultItem;
            });

            searchSuggestionResults.replaceChildren(...searchSuggestionLinks);
            if (searchSuggestionResults.firstElementChild) {
                searchSuggestionResults.firstElementChild.tabIndex = 0;
            }
            addResultsPageEntry();
        }

        const debounce = (func, timeout = 500) => {
            let timeoutId;
            return (...args) => {
                clearTimeout(timeoutId);
                timeoutId = setTimeout(() => {
                    func(...args);
                }, timeout);
            };
        };

        const processSearchInput = (query, searchWorker) => {
            if (query.length >= 1) {
                searchWorker.postMessage({
                    type: 'search-request',
                    query
                });
            } else {
                populateSearchSuggestions([]);
            }
        }
        const debounceSearch = debounce(processSearchInput);

        // Creates the Web Worker, to overcome the Same-Origin policy the URL is passed to the worker.
        const searchWorkerBlob = new Blob([searchWorkerTemplate.textContent]);
        const searchWorker = new Worker(URL.createObjectURL(searchWorkerBlob));

        // send page url to the worker, for script loading
        let locationOrigin = window.location.protocol
            + "//"
            + window.location.hostname
            + (
                window.location.port
                ? ':' + window.location.port
                : ''
            );
        var pageLocation = locationOrigin + window.location.pathname;
        var url = pageLocation.substr(0, pageLocation.lastIndexOf('/') + 1);
        searchWorker.postMessage({ type: "setup", baseUrl: url });
        searchWorker.addEventListener('message', (event) => {
            var message = event.data;
            if (message.type === 'search-results') {
                populateSearchSuggestions(message.results);
            }
        })

        // calling preventDefault on the search result suggestion prevents the search input field from losing the focus
        // otherwise the blur event from that would close the search result dropdown before the click on the result registers
        searchSuggestionResults.addEventListener('mousedown', (event) => event.preventDefault(), false);

        searchSuggestionResults.addEventListener('mouseover', (ev) => {
            if (ev.target.matches('.exp-search-suggestion-option')) {
                selectSuggestion(
                    getActiveSearchSuggestionElement(),
                    ev.target.parentElement
                );
            }
        }, false);

        function selectSuggestion(previousActive, newActive) {
            showSearchSuggestions();
            if (previousActive && newActive) {
                previousActive.tabIndex = -1;
                newActive.tabIndex = 0;
                newActive.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }
        }

        function getActiveSearchSuggestionElement() {
            return searchSuggestionResults.querySelector('.exp-search-suggestion-option-container[tabindex = "0"]')
                || searchSuggestionResults.firstElementChild;
        }

        // bind handlers for search input fields
        searchInputField.addEventListener('focus', showSearchSuggestions, false);
        searchInputField.addEventListener('blur', hideSearchSuggestions, false);
        searchInputField.addEventListener('input', (ev) => {
            const query = ev.target.value;
            debounceSearch(query, searchWorker);
        }, false);

        // add keyboard navigation to search dropdown
        searchInputField.addEventListener('keydown', (event) => {
            const activeElement = getActiveSearchSuggestionElement();

            function selectNextSuggestion() {
                selectSuggestion(activeElement, activeElement.nextElementSibling);
            }

            function selectPreviousSuggestion() {
                selectSuggestion(activeElement, activeElement.previousElementSibling);
            }

            function navigateToActiveSuggestionPage() {
                if (activeElement) {
                    const link = activeElement.querySelector('a');
                    if (link) {
                        link.click();
                    }
                }
            }

            switch (event.key) {
                case 'ArrowUp':
                    event.preventDefault();
                    selectPreviousSuggestion();
                    break;
                case 'ArrowDown':
                    event.preventDefault();
                    selectNextSuggestion();
                    break;
                case 'Enter':
                    event.preventDefault();
                    navigateToActiveSuggestionPage();
                    break;
                case 'Escape':
                    event.preventDefault();
                    searchInputField.blur();
                    break;
                default:
                    break;
            }
        }, false);

    }
});