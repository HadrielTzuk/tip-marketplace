function get_organizations_departments(organizations) {
    if(!organizations || organizations === "N/A") {
        return "N/A";
    }

    return organizations
        .filter(organization => organization.department)
        .map(organization => organization.department)
        .join();
}
