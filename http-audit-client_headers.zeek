@load base/protocols/http/main

module HTTP;

# Add specific HTTP field to http logs
redef HTTP::proxy_headers += {
    "TRUE-CLIENT-IP" 
};

export {
    redef record Info += {
        cookie:			string &log &optional;
        true_client_ip:		string &log &optional;
    };
    
    option log_cookie = T;
    option log_true_client_ip = T;
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
  {
    if ( ! c?$http )
        return;

    if ( is_orig )
        {
        if ( log_true_client_ip )
            {
            if ( name == "TRUE-CLIENT-IP" )
                c$http$true_client_ip = value;
            }
        
        if ( log_cookie )
            {
            if ( name == "COOKIE" )
                c$http$cookie = value;
            }
        }
  }
