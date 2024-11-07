!function(e) {
    var t = {};

    function n(o) {
        if (t[o]) return t[o].exports;
        var r = t[o] = { i: o, l: !1, exports: {} };
        return e[o].call(r.exports, r, r.exports, n), r.l = !0, r.exports
    }

    n.m = e, n.c = t, n.d = function(e, t, o) {n.o(e, t) || Object.defineProperty(e, t, { enumerable: !0, get: o })}, n.r = function(e) {
        "undefined" != typeof Symbol && Symbol.toStringTag && Object.defineProperty(e, Symbol.toStringTag,
            { value: "Module" }), Object.defineProperty(e, "__esModule", { value: !0 })
    }, n.t = function(e, t) {
        if (1 & t && (e = n(e)), 8 & t) return e;
        if (4 & t && "object" == typeof e && e && e.__esModule) return e;
        var o = Object.create(null);
        if (n.r(o), Object.defineProperty(o, "default", { enumerable: !0, value: e }), 2 & t && "string" != typeof e) for (var r in e) n.d(
            o, r, function(t) {return e[t]}.bind(null, r));
        return o
    }, n.n = function(e) {
        var t = e && e.__esModule ? function() {return e.default} : function() {return e};
        return n.d(t, "a", t), t
    }, n.o = function(e, t) {return Object.prototype.hasOwnProperty.call(e, t)}, n.p = "theme/", n(n.s = 12)
}([function(e, t, n) {
    (function(o) {
        var r, l, s, i;
        i = void 0 !== o ? o : this.window || this.global, l = [], r = function(e) {
            "use strict";
            var t, o, r = n(3), l = {}, s = {}, i = n(4), c = n(5);
            if ("undefined" != typeof window) {
                var a, u = !!e.document.querySelector && !!e.addEventListener, d = Object.prototype.hasOwnProperty;
                return s.destroy = function() {
                    try {
                        document.querySelector(l.tocSelector).innerHTML = ""
                    } catch (e) {
                        console.warn("Element not found: " + l.tocSelector)
                    }
                    l.scrollContainer && document.querySelector(l.scrollContainer) ? (document.querySelector(
                        l.scrollContainer).removeEventListener("scroll", this._scrollListener, !1), document.querySelector(
                        l.scrollContainer).removeEventListener("resize", this._scrollListener, !1), t && document.querySelector(
                        l.scrollContainer).removeEventListener("click", this._clickListener, !1)) : (document.removeEventListener("scroll",
                        this._scrollListener, !1), document.removeEventListener("resize", this._scrollListener, !1), t
                    && document.removeEventListener("click", this._clickListener, !1))
                }, s.init = function(e) {
                    if (u && (l = m(r, e || {}), this.options = l, this.state = {}, l.scrollSmooth && (l.duration =
                        l.scrollSmoothDuration, l.offset = l.scrollSmoothOffset, s.scrollSmooth = n(6).initSmoothScrolling(l)), t =
                        i(l), o = c(l), this._buildHtml = t, this._parseContent = o, s.destroy(), null !== (a =
                        o.selectHeadings(l.contentSelector, l.headingSelector)))) {
                        var d = o.nestHeadingsArray(a).nest;
                        t.render(l.tocSelector, d), this._scrollListener = f((function(e) {
                            t.updateToc(a);
                            var n = e && e.target && e.target.scrollingElement && 0 === e.target.scrollingElement.scrollTop;
                            (e && (0 === e.eventPhase || null === e.currentTarget) || n) && (t.updateToc(a), l.scrollEndCallback
                            && l.scrollEndCallback(e))
                        }), l.throttleTimeout), this._scrollListener(), l.scrollContainer && document.querySelector(l.scrollContainer)
                                                                        ? (document.querySelector(l.scrollContainer).addEventListener(
                                "scroll", this._scrollListener, !1), document.querySelector(l.scrollContainer).addEventListener("resize",
                                this._scrollListener, !1)) : (document.addEventListener("scroll", this._scrollListener,
                                !1), document.addEventListener("resize", this._scrollListener, !1));
                        var p = null;
                        return this._clickListener = f((function(e) {
                            l.scrollSmooth && t.disableTocAnimation(e), t.updateToc(a), p && clearTimeout(p), p =
                                setTimeout((function() {t.enableTocAnimation()}), l.scrollSmoothDuration)
                        }), l.throttleTimeout), l.scrollContainer && document.querySelector(l.scrollContainer) ? document.querySelector(
                            l.scrollContainer).addEventListener("click", this._clickListener, !1) : document.addEventListener("click",
                            this._clickListener, !1), this
                    }
                }, s.refresh = function(e) {s.destroy(), s.init(e || this.options)}, e.tocbot = s, s
            }

            function m() {
                for (var e = {}, t = 0; t < arguments.length; t++) {
                    var n = arguments[t];
                    for (var o in n) d.call(n, o) && (e[o] = n[o])
                }
                return e
            }

            function f(e, t, n) {
                var o, r;
                return t || (t = 250), function() {
                    var l = n || this, s = +new Date, i = arguments;
                    o && s < o + t ? (clearTimeout(r), r = setTimeout((function() {o = s, e.apply(l, i)}), t)) : (o = s, e.apply(l, i))
                }
            }
        }(i), void 0 === (s = "function" == typeof r ? r.apply(t, l) : r) || (e.exports = s)
    }).call(this, n(2))
}, function(e, t, n) {}, function(e, t) {
    var n;
    n = function() {return this}();
    try {
        n = n || new Function("return this")()
    } catch (e) {
        "object" == typeof window && (n = window)
    }
    e.exports = n
}, function(e, t) {
    e.exports = {
        tocSelector: ".js-toc",
        contentSelector: ".js-toc-content",
        headingSelector: "h1, h2, h3",
        ignoreSelector: ".js-toc-ignore",
        linkClass: "toc-link",
        extraLinkClasses: "",
        activeLinkClass: "is-active-link",
        listClass: "toc-list",
        extraListClasses: "",
        isCollapsedClass: "is-collapsed",
        collapsibleClass: "is-collapsible",
        listItemClass: "toc-list-item",
        activeListItemClass: "is-active-li",
        collapseDepth: 0,
        scrollSmooth: !0,
        scrollSmoothDuration: 420,
        scrollSmoothOffset: 0,
        scrollEndCallback: function(e) {},
        headingsOffset: 1,
        throttleTimeout: 50,
        positionFixedSelector: null,
        positionFixedClass: "is-position-fixed",
        fixedSidebarOffset: "auto",
        includeHtml: !1,
        onClick: !1,
        orderedList: !0,
        scrollContainer: null
    }
}, function(e, t) {
    e.exports = function(e) {
        var t = [].forEach, n = [].some, o = document.body, r = !0, l = " ";

        function s(n, o) {
            var r = o.appendChild(function(n) {
                var o = document.createElement("li"), r = document.createElement("a");
                e.listItemClass && o.setAttribute("class", e.listItemClass);
                e.onClick && (r.onclick = e.onClick);
                e.includeHtml && n.childNodes.length ? t.call(n.childNodes, (function(e) {r.appendChild(e.cloneNode(!0))}))
                                                     : r.textContent = n.textContent;
                return r.setAttribute("href", "#" + n.id), r.setAttribute("class",
                    e.linkClass + l + "node-name--" + n.nodeName + l + e.extraLinkClasses), o.appendChild(r), o
            }(n));
            if (n.children.length) {
                var c = i(n.isCollapsed);
                n.children.forEach((function(e) {s(e, c)})), r.appendChild(c)
            }
        }

        function i(t) {
            var n = e.orderedList ? "ol" : "ul", o = document.createElement(n), r = e.listClass + l + e.extraListClasses;
            return t && (r += l + e.collapsibleClass, r += l + e.isCollapsedClass), o.setAttribute("class", r), o
        }

        function c(t) {
            return -1 !== t.className.indexOf(e.collapsibleClass) && -1 !== t.className.indexOf(e.isCollapsedClass) ? (t.className =
                t.className.split(l + e.isCollapsedClass).join(""), c(t.parentNode.parentNode)) : t
        }

        return {
            enableTocAnimation: function() {r = !0}, disableTocAnimation: function(t) {
                var n = t.target || t.srcElement;
                "string" == typeof n.className && -1 !== n.className.indexOf(e.linkClass) && (r = !1)
            }, render: function(e, t) {
                var n = i(!1);
                t.forEach((function(e) {s(e, n)}));
                var o = document.querySelector(e);
                if (null !== o) return o.firstChild && o.removeChild(o.firstChild), 0 === t.length ? o : o.appendChild(n)
            }, updateToc: function(s) {
                if (e.scrollContainer && document.querySelector(e.scrollContainer)) var i = document.querySelector(
                    e.scrollContainer).scrollTop; else i = document.documentElement.scrollTop || o.scrollTop;
                e.positionFixedSelector && function() {
                    if (e.scrollContainer && document.querySelector(e.scrollContainer)) var t = document.querySelector(
                        e.scrollContainer).scrollTop; else t = document.documentElement.scrollTop || o.scrollTop;
                    var n = document.querySelector(e.positionFixedSelector);
                    "auto" === e.fixedSidebarOffset && (e.fixedSidebarOffset = document.querySelector(e.tocSelector).offsetTop), t
                                                                                                                                 > e.fixedSidebarOffset
                                                                                                                                 ? -1
                                                                                                                                     === n.className.indexOf(
                            e.positionFixedClass) && (n.className += l + e.positionFixedClass) : n.className = n.className.split(
                            l + e.positionFixedClass).join("")
                }();
                var a, u = s;
                if (r && null !== document.querySelector(e.tocSelector) && u.length > 0) {
                    n.call(u, (function(t, n) {
                        return t.offsetTop > i + e.headingsOffset + 10 ? (a = u[0 === n ? n : n - 1], !0) : n === u.length - 1 ? (a =
                            u[u.length - 1], !0) : void 0
                    }));
                    var d = document.querySelector(e.tocSelector).querySelectorAll("." + e.linkClass);
                    t.call(d, (function(t) {t.className = t.className.split(l + e.activeLinkClass).join("")}));
                    var m = document.querySelector(e.tocSelector).querySelectorAll("." + e.listItemClass);
                    t.call(m, (function(t) {t.className = t.className.split(l + e.activeListItemClass).join("")}));
                    var f = document.querySelector(e.tocSelector).querySelector(
                        "." + e.linkClass + ".node-name--" + a.nodeName + '[href="#' + a.id + '"]');
                    -1 === f.className.indexOf(e.activeLinkClass) && (f.className += l + e.activeLinkClass);
                    var p = f.parentNode;
                    p && -1 === p.className.indexOf(e.activeListItemClass) && (p.className += l + e.activeListItemClass);
                    var h = document.querySelector(e.tocSelector).querySelectorAll("." + e.listClass + "." + e.collapsibleClass);
                    t.call(h, (function(t) {
                        -1 === t.className.indexOf(e.isCollapsedClass) && (t.className += l + e.isCollapsedClass)
                    })), f.nextSibling && -1 !== f.nextSibling.className.indexOf(e.isCollapsedClass) && (f.nextSibling.className =
                        f.nextSibling.className.split(l + e.isCollapsedClass).join("")), c(f.parentNode.parentNode)
                }
            }
        }
    }
}, function(e, t) {
    e.exports = function(e) {
        var t = [].reduce;

        function n(e) {return e[e.length - 1]}

        function o(e) {return +e.nodeName.split("H").join("")}

        function r(t) {
            var n = { id: t.id, children: [], nodeName: t.nodeName, headingLevel: o(t), textContent: t.textContent.trim() };
            return e.includeHtml && (n.childNodes = t.childNodes), n
        }

        return {
            nestHeadingsArray: function(l) {
                return t.call(l, (function(t, l) {
                    return function(t, l) {
                        for (var s = r(t), i = o(t), c = l, a = n(c), u = i - (a ? a.headingLevel : 0); u > 0;) (a = n(c)) && void 0
                        !== a.children && (c = a.children), u--;
                        i >= e.collapseDepth && (s.isCollapsed = !0), c.push(s)
                    }(r(l), t.nest), t
                }), { nest: [] })
            }, selectHeadings: function(t, n) {
                var o = n;
                e.ignoreSelector && (o = n.split(",").map((function(t) {return t.trim() + ":not(" + e.ignoreSelector + ")"})));
                try {
                    return document.querySelector(t).querySelectorAll(o)
                } catch (e) {
                    return console.warn("Element not found: " + t), null
                }
            }
        }
    }
}, function(e, t) {
    t.initSmoothScrolling = function(e) {
        document.documentElement.style;
        var t = e.duration, n = e.offset, o = location.hash ? r(location.href) : location.href;

        function r(e) {return e.slice(0, e.lastIndexOf("#"))}

        document.body.addEventListener("click", (function(l) {
            var s;
            "a" !== (s = l.target).tagName.toLowerCase() || !(s.hash.length > 0 || "#" === s.href.charAt(s.href.length - 1)) || r(s.href)
            !== o && r(s.href) + "#" !== o || l.target.className.indexOf("no-smooth-scroll") > -1 || "#" === l.target.href.charAt(
                l.target.href.length - 2) && "!" === l.target.href.charAt(l.target.href.length - 1) || -1 === l.target.className.indexOf(
                e.linkClass) || function(e, t) {
                var n, o, r = window.pageYOffset,
                    l = { duration: t.duration, offset: t.offset || 0, callback: t.callback, easing: t.easing || d },
                    s = document.querySelector('[id="' + decodeURI(e).split("#").join("") + '"]'),
                    i = "string" == typeof e ? l.offset + (e ? s && s.getBoundingClientRect().top || 0
                                                             : -(document.documentElement.scrollTop || document.body.scrollTop)) : e,
                    c = "function" == typeof l.duration ? l.duration(i) : l.duration;

                function a(e) {o = e - n, window.scrollTo(0, l.easing(o, r, i, c)), o < c ? requestAnimationFrame(a) : u()}

                function u() {window.scrollTo(0, r + i), "function" == typeof l.callback && l.callback()}

                function d(e, t, n, o) {return (e /= o / 2) < 1 ? n / 2 * e * e + t : -n / 2 * (--e * (e - 2) - 1) + t}

                requestAnimationFrame((function(e) {n = e, a(e)}))
            }(l.target.hash, {
                duration: t, offset: n, callback: function() {
                    var e, t;
                    e = l.target.hash, (t = document.getElementById(e.substring(1))) && (/^(?:a|select|input|button|textarea)$/i.test(
                        t.tagName) || (t.tabIndex = -1), t.focus())
                }
            })
        }), !1)
    }
}, function(e, t) {
    function n(e) {
        const t = e.currentTarget;
        e.target.matches(".expand-control-text") && t.classList.toggle("expanded")
    }

    document.querySelectorAll(".expand-container").forEach((e => e.addEventListener("click", n, !1)))
}, function(e, t) {
    function n(e) {
        return function(e) {
            const t = getComputedStyle(e);
            return "none" !== t.display && "hidden" !== t.visibility && "1" === t.opacity && t.zoom >= 1 && "none" === t.transform
        }(e) && function(e) {
            if (!e.parentElement) return !0;
            const t = e.getBoundingClientRect(), n = e.getBoundingClientRect();
            return n.x <= t.x && n.y <= t.y && n.right >= t.right && n.bottom >= t.bottom
        }(e) && function(e, t, n) {
            const o = e.getBoundingClientRect();
            return o.width >= t && o.height >= n
        }(e, 10, 10) && function(e) {
            const t = e.parentElement;
            if (t) return n(t);
            return !0
        }(e)
    }

    document.querySelector('meta[name="k15t-cxp-html-licensing-watermark"]') && setTimeout((() => {
        if (!function() {
            const e = document.querySelector(".html-licensing-watermark");
            return e && n(e)
        }()) {
            const e = "https://marketplace.atlassian.com/apps/420604/scroll-html-exporter-for-confluence?hosting=cloud&tab=overview",
                t = document.createElement("div");
            t.style.backgroundColor = "var(--vp-footer-background-color)";
            const n = document.createElement("a");
            n.style.color = "var(--vp-footer-text-color)", n.href = e, n.textContent = e, t.appendChild(n), document.body.appendChild(t)
        }
    }), 1e4 * Math.random())
}, function(e, t) {
    const n = document.querySelector("#vp-js-mobile__navigation .vp-button"), o = document.querySelector("#exp-navigation-wrapper"),
        r = document.querySelector("#exp-navigation-wrapper iframe");
    n.addEventListener("click", (() => {
        const e = r.getAttribute("src");
        if (!e.includes("mobile")) {
            let t = e + "&mobile";
            e.includes("?") || (t = e + "?mobile"), r.setAttribute("src", t)
        }
        n.classList.toggle("is-menu-open"), "hidden xl:block exp-mobile-navigation__popup".split(" ").forEach(
            (e => o.classList.toggle(e))), document.querySelector("body").classList.toggle("exp-mobile-navigation-visible")
    }))
}, function(e, t) {
    const n = document.querySelector("#search-worker"), o = document.querySelector("#search-texbox"),
        r = document.querySelector("#search-suggestion-container");
    if (n && o && r) {
        function l() {r.classList.remove("hidden")}

        function s(e) {
            const t = document.querySelector("#search-suggestion-option-template"), n = e.slice(0, 3).map((e => {
                const n = t.content.cloneNode(!0), o = n.querySelector("a");
                return o.textContent = e.title, o.href = e.link, n
            }));
            r.replaceChildren(...n), r.firstElementChild && (r.firstElementChild.tabIndex = 0), function() {
                let e = "search.html?searchQuery=" + encodeURIComponent(o.value), t = document.createElement("div");
                t.id = "see-all-results", t.className = "vp-search-suggestion-option-container vp-search-form__suggestion", t.tabIndex = -1;
                let n = document.createElement("a");
                n.href = e, n.className = "vp-search-suggestion-option vp-search-form__suggestion search-suggestions-see-all-item", n.text =
                    "See all search results", t.append(n), r.append(t)
            }()
        }

        const e = (e, t) => {e.length >= 1 ? t.postMessage({ type: "search-request", query: e }) : s([])}, t = ((e, t = 500) => {
            let n;
            return (...o) => {clearTimeout(n), n = setTimeout((() => {e(...o)}), t)}
        })(e), a = new Blob([n.textContent]), u = new Worker(URL.createObjectURL(a));
        var i = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ":" + window.location.port : "")
            + window.location.pathname, c = i.substr(0, i.lastIndexOf("/") + 1);
        u.postMessage({ type: "setup", baseUrl: c }), u.addEventListener("message", (e => {
            var t = e.data;
            "search-results" === t.type && s(t.results)
        })), r.addEventListener("mousedown", (e => e.preventDefault()), !1), o.addEventListener("focus", l, !1), o.addEventListener("blur",
            (function() {r.classList.add("hidden")}), !1), o.addEventListener("input", (e => {
            const n = e.target.value;
            t(n, u)
        }), !1), o.addEventListener("keydown", (e => {
            const t = r.querySelector('.vp-search-suggestion-option-container[tabindex = "0"]') || r.firstElementChild;

            function n(e, t) {
                l(), e && t && (e.tabIndex = -1, t.tabIndex = 0, t.scrollIntoView({ behavior: "smooth", block: "nearest" }))
            }

            switch (e.key) {
                case"ArrowUp":
                    e.preventDefault(), n(t, t.previousElementSibling);
                    break;
                case"ArrowDown":
                    e.preventDefault(), n(t, t.nextElementSibling);
                    break;
                case"Enter":
                    e.preventDefault(), function() {
                        if (t) {
                            const e = t.querySelector("a");
                            e && e.click()
                        }
                    }();
                    break;
                case"Escape":
                    e.preventDefault(), o.blur()
            }
        }), !1)
    }
}, function(e, t) {
    function n(e) {
        e.preventDefault();
        const t = e.target.closest("a");
        for (const e of t.closest("ul.tabs-menu").getElementsByClassName("menu-item")) e.classList.remove("active-tab");
        t.parentElement.classList.add("active-tab");
        const n = decodeURIComponent(t.hash).substring(1);
        for (const e of t.closest("div.aui-tabs").getElementsByClassName("tabs-pane")) e.classList.remove("active-pane");
        document.getElementById(n).classList.add("active-pane")
    }

    document.querySelectorAll("ul.tabs-menu > li.menu-item a").forEach((e => e.addEventListener("click", n, !1)))
}, function(e, t, n) {
    "use strict";
    n.r(t);
    n(1);
    var o = n(0);
    let r;
    const l = () => (r || (r = document.querySelector("header.header")), r ? r.getBoundingClientRect().height : 74),
        s = document.querySelector(".js-tocBot"), i = document.querySelector(".toc-list");
    if (s) {
        const e = "article__toc__link";
        o.init({
            tocSelector: ".js-tocBot",
            contentSelector: ".js-tocBot-content",
            linkClass: e,
            activeLinkClass: "article__toc__link--active",
            headingSelector: "h1, h2, h3, h4",
            scrollSmooth: !0,
            scrollSmoothDuration: 500,
            headingsOffset: l() + 32,
            scrollSmoothOffset: -l() - 32,
            collapseDepth: 6,
            disableTocScrollSync: !0
        }), i && (s.style.marginBottom = "3em")
    }
    n(7), n(8), n(9), n(10), n(11)
}]);