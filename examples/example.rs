use ad_helper::AttributeHelper;
use ldap3::{
    adapters::{Adapter, EntriesOnly, PagedResults},
    Scope, SearchEntry,
};

#[tokio::main]
async fn main() {
    let users = ["JSmith"]; // SAM Account Name of user; no fixed limit of users
    let page_size = 1500;
    let mut ldap_conn = ad_helper::autoconnect_ldap(None).await.unwrap();
    let filter = ad_helper::generate_bulk_filter(&users, "user", "samaccountname");
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(page_size as _)),
    ];
    let base = "dc=contoso,dc=com";
    let scope = Scope::Subtree;
    let attrs = [
        "samaccountname",
        "memberof",
        "employeeid",
        "employeenumber",
        "title",
        "department",
        "displayName",
        "sid",
        "objectsid",
        "lastlogontimestamp",
    ];
    let mut search = ldap_conn
        .streaming_search_with(adapters, base, scope, &filter, attrs)
        .await
        .unwrap();

    // Iterate through search results until no more remain
    while let Some(result_entry) = search
        .next()
        .await
        .unwrap_or_else(|e| panic!("Error: Failed to search AD\nReason: {e}"))
    {
        let mut result = SearchEntry::construct(result_entry);

        let sam = result.str_attr("sAMAccountName").unwrap_or_default();

        let num = result.str_attr("employeeNumber").unwrap_or_default();
        let eid = result.str_attr("employeeID").unwrap_or_default();
        let title = result.str_attr("department").unwrap_or_default();
        let department = result.str_attr("title").unwrap_or_default();
        let name = result.str_attr("displayName").unwrap_or_default();

        let groups = result
            .member_of()
            .unwrap_or_default()
            .into_iter()
            .take(5)
            .collect::<Vec<_>>(); // Only show first 10 groups
        let sid = result.sid().unwrap_or_default();
        let enabled = result.enabled();
        let llts = result.last_logon();
        let dn = result.dn;

        println!(
            "
        DistinguishedName:  {dn}
        Enabled:            {enabled}
        Name:               {name}
        SamAccountName:     {sam}
        LastLogonTimeStamp: {llts}
        EmployeeID:         {eid}
        EmployeeNumber:     {num}
        Title:              {title}
        Department:         {department}
        MemberOf:           {:?} ...
        SID:                {sid}
        ",
            groups
        );
    }
}
