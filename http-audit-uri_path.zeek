@load base/protocols/http/main

module HTTP;

export {
    redef record Info += {
        uri_path: string &log &optional;
    };

    option log_uri_path = T;
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
  {
    if ( ! c?$http )
        return;

    if ( log_uri_path )
        c$http$uri_path = split_string(unescaped_URI, /\?/)[0];
  }
