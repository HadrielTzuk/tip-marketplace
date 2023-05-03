function createTitleId(external_references) {
    return external_references
        .map(el => {
            if (el.source_name === "mitre-attack") {
                const url = el.url ? el.url : "N/A";
                if (url === "N/A") {
                    return "N/A";
                } else {
                    return `<a href=${url} target="_blank" class="link">${el.external_id}</a>`;
                }
            }
        })
        .filter(x => x !== undefined);
}