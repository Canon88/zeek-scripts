global local_sites: set[string] = {
    "www.google.com",
    "ifconfig.io"
};

function is_local_site(rec: HTTP::Info): bool
    {
    return rec$host in local_sites;
    }

event zeek_init()
    {
    # First remove the default filter.
    Log::remove_default_filter(HTTP::LOG);

    # Add the filter to direct logs to the appropriate file name.
    local filter: Log::Filter = [$name="http_filter", $pred=is_local_site];
    Log::add_filter(HTTP::LOG, filter);
    }
