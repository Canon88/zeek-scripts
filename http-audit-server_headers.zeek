@load base/protocols/http/main

module HTTP;

export {
    redef record Info += {
        set_cookie:		string &log &optional;
    };
    
    option log_set_cookie = T;
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
  {
    if ( ! c?$http )
        return;

    if ( ! is_orig )
        {
        if ( log_set_cookie )
            {
            if ( name == "SET-COOKIE" )
                c$http$set_cookie = value;
            }
        }
  }
