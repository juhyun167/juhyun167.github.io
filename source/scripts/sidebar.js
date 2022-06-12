function insertAfter(newNode, referenceNode) {
    referenceNode.parentNode.insertBefore(newNode, referenceNode.nextSibling);
}

// construct list of categories 
let category_list = [{ name: "About", href: "/about/", count: 1 }]; // hardcoded page exists
let ul_elem = document.getElementsByClassName("category-list")[0];

for (let i = 0; i < ul_elem.children.length; i++) {
    let li_elem = ul_elem.children[i];
    let a_elem = li_elem.getElementsByClassName("category-list-link")[0];
    
    let name = a_elem.innerText;
    let href = a_elem.href;
    let count = li_elem.getElementsByTagName("span")[0].innerText;
    let has_child = li_elem.getElementsByClassName("category-list-child")[0] !== undefined;

    if (has_child) {
        let child_category_list = [];
        let child_ul_elem = li_elem.getElementsByClassName("category-list-child")[0];

        for (let j = 0; j < child_ul_elem.children.length; j++) {
            let child_li_elem = child_ul_elem.children[i];
            let child_a_elem = child_li_elem.getElementsByClassName("category-list-link")[0];

            let child_name = child_a_elem.innerText;
            let child_href = child_a_elem.href;
            let child_count = child_li_elem.getElementsByTagName("span")[0].innerText;

            child_category_list.push({ name: child_name, href: child_href, count: child_count });
        }

        category_list.push({ name, href, count, child_category_list });
    } else {
        category_list.push({ name, href, count });
    }
}

// build a new element for list of categories
let new_ul_elem = document.createElement("ul");
new_ul_elem.setAttribute("class", "new-category-list");

for (let i = 0; i < category_list.length; i++) {
    let el = category_list[i];
    let li_elem = document.createElement("li");
    let a_elem = document.createElement("a");
    a_elem.setAttribute("class", "new-category-list-link")
    a_elem.href = el.href;
    a_elem.innerText = " " + el.name + " ";
    if (i === category_list.length - 1) {
        li_elem.setAttribute("class", "last-index-list-item");
    }

    let span_elem = document.createElement("span");
    span_elem.setAttribute("class", "post-count");
    span_elem.innerText = "(" + el.count + ")";
    a_elem.appendChild(span_elem);

    let div_elem = document.createElement("div");       // only for hover trick
    div_elem.setAttribute("class", "new-category-list-container");
    div_elem.innerHTML = "&nbsp;&nbsp;";
    
    // add link to list item
    div_elem.appendChild(a_elem);
    
    // build element for child category list
    let child_ul_elem = document.createElement("ul");
    child_ul_elem.setAttribute("class", "child-category-list");
    
    if ("child_category_list" in el) {       // has children
        let btn_elem = document.createElement("button");
        btn_elem.setAttribute("class", "close fa-solid fa-angle-down");
        btn_elem.onclick = (event) => {
            let btn = event.target;
            if (btn.className.includes("close")) {
                btn.setAttribute("class", "open fa-solid fa-angle-up");
            } else {
                btn.setAttribute("class", "close fa-solid fa-angle-down");
            }

            btn.parentElement.nextSibling.classList.toggle("collapsed");
        };

        for (let child of el.child_category_list) {
            let child_li_elem = document.createElement("li");
            let child_a_elem = document.createElement("a");
            child_a_elem.setAttribute("class", "new-category-list-link")
            child_a_elem.href = child.href;
            child_a_elem.innerText = " " + child.name + " ";
            child_li_elem.innerHTML = "&nbsp;&nbsp;";

            let child_span_elem = document.createElement("span");
            child_span_elem.setAttribute("class", "post-count");
            child_span_elem.innerText = "(" + child.count + ")";
            child_a_elem.appendChild(child_span_elem);

            let i_elem = document.createElement("i");
            i_elem.setAttribute("class", "fa-solid fa-arrow-right");

            let child_div_elem = document.createElement("div");
            child_div_elem.setAttribute("class", "new-category-list-container");

            child_li_elem.appendChild(i_elem);
            child_li_elem.appendChild(child_a_elem)

            child_div_elem.appendChild(child_li_elem);
            child_ul_elem.appendChild(child_div_elem);
        }

        // add children toggle button to list item
        div_elem.appendChild(btn_elem);
    }

    // register to category list
    li_elem.appendChild(div_elem);
    if ("child_category_list" in el) {
        let collapsible_wrapper = document.createElement("div");
        let collapsible = document.createElement("div");
        collapsible_wrapper.setAttribute("class", "collapsible-wrapper collapsed");
        collapsible.setAttribute("class", "collapsible");

        collapsible.appendChild(child_ul_elem);
        collapsible_wrapper.appendChild(collapsible);
        li_elem.appendChild(collapsible_wrapper);
    }
    new_ul_elem.appendChild(li_elem);
}

// replace old element with new element
insertAfter(new_ul_elem, ul_elem);
ul_elem.remove();

// list of social services
let social_list = [
    { name: "Facebook", href: "https://fb.com/hackrabbit    ", icon_link: "https://cdn.jsdelivr.net/gh/kaniwari/fcresources@1.0/favicon/facebook.png" },
    { name: "Github", href: "https://github.com/juhyun167", icon_link: "https://cdn.jsdelivr.net/gh/kaniwari/fcresources@1.0/favicon/github.png" }
];
let social_ul_elem = document.createElement("ul");
social_ul_elem.setAttribute("class", "new-category-list");

for (let i = 0; i < social_list.length; i++) {
    let el = social_list[i];
    let li_elem = document.createElement("li");
    let a_elem = document.createElement("a");
    a_elem.setAttribute("class", "new-category-list-link")
    a_elem.href = el.href;
    a_elem.innerText = " " + el.name + " ";
    if (i === social_list.length - 1) {
        li_elem.setAttribute("class", "last-index-list-item");
    }

    let div_elem = document.createElement("div");       // only for hover trick
    div_elem.setAttribute("class", "new-category-list-container");
    div_elem.innerHTML = "&nbsp;&nbsp;";

    let img_elem = document.createElement("img");
    img_elem.setAttribute("class", "social-icon");
    img_elem.setAttribute("src", el.icon_link);
    
    // add link to list item
    div_elem.appendChild(img_elem);
    div_elem.appendChild(a_elem);
    li_elem.appendChild(div_elem);
    social_ul_elem.appendChild(li_elem);
}

insertAfter(social_ul_elem, new_ul_elem);