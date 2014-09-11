#Wrapper around liboauth POSIX-c functions implementing the OAuth Core RFC 5849 standard
#http://liboauth.sourceforge.net/index.html

module OAuth

########################################################################################
#
#
#	Exports & Constants
#
#
########################################################################################

export 
oauth_gen_nonce,
oauth_sign_hmac_sha1,
oauth_sign_hmac_sha1_raw,
oauth_sign_plaintext,
#oauth_sign_rsa_sha1,
#oauth_verify_rsa_sha1,
#oauth_split_url_parameters,
#oauth_split_post_parameters,
#oauth_serialize_url,
#oauth_serialize_url_sep,
#oauth_serialize_url_parameters,
#oauth_cmpstringp,
#oauth_param_exists,
#oauth_add_param_to_array,
#oauth_free_array,
#oauth_time_independent_equals_n,
#oauth_time_independent_equals,
#oauth_sign_url2,
#oauth_sign_array2_process,
#oauth_sign_array2,
#oauth_body_hash_file,
#oauth_body_hash_data,
#oauth_body_hash_encode,
#oauth_sign_xmpp,
#oauth_encode_base64,
#oauth_decode_base64,
oauth_url_escape
#oauth_url_unescape,
#oauth_catenc


# What benefit does this provide, when OAuthMethod provided below?
# begin enum ANONYMOUS_1
typealias ANONYMOUS_1 Uint32
const OA_HMAC = (uint32)(0)
const OA_RSA = (uint32)(1)
const OA_PLAINTEXT = (uint32)(2)
# end enum ANONYMOUS_1


# begin enum OAuthMethod
typealias OAuthMethod Uint32
const OA_HMAC = (uint32)(0)
const OA_RSA = (uint32)(1)
const OA_PLAINTEXT = (uint32)(2)
# end enum OAuthMethod



#TODO: Make this generic for all operating systems
#Do we need to use Homebrew or BinDeps to install liboauth for people or assume they installed themselves?
@osx? (const LIBOAUTH = "/usr/local/lib/liboauth.dylib")
@windows? ()
@linux?()
@unix?()

########################################################################################
#
#
#	Functions
#
#
########################################################################################

#Seems correct, returns random string
function oauth_gen_nonce()
    result = ccall((:oauth_gen_nonce,LIBOAUTH),Ptr{Uint8},())
    if result == C_NULL
        error("oauth_gen_nonce failed")
    end
    return bytestring(result)
end

#Should be correct
function oauth_sign_hmac_sha1(url::String,key::String)
    result = ccall((:oauth_sign_hmac_sha1,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8}),url,key)
    if result == C_NULL
        error("oauth_sign_hmac_sha1 failed")
    end
    return bytestring(result)
end

#Is this right? Do I need to convert the first Ptr{Uint8} in ccall to String type?
function oauth_sign_hmac_sha1_raw(message::String,messagelength::Integer,key::String,keylength::Integer)
    result = ccall((:oauth_sign_hmac_sha1_raw,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Cint,Ptr{Uint8},Cint),message,messagelength,key,keylength)
    if result == C_NULL
        error("oauth_sign_hmac_sha1_raw failed")
    end
    return bytestring(result)
end

#Is this right? Not sure of value of this function, if it just returns the key value
function oauth_sign_plaintext(message::String,key::String)
    result = ccall((:oauth_sign_plaintext,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8}),message,key)
    if result == C_NULL
        error("oauth_sign_plaintext failed")
    end
    return bytestring(result)
end

#Only modified argument names & types
function oauth_sign_rsa_sha1(message::String,key::String)
    result = ccall((:oauth_sign_rsa_sha1,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Ptr{Uint8}),message,key)
    if result == C_NULL
        error("oauth_sign_rsa_sha1 failed")
    end
    return bytestring(result)
end

#Only modified argument names & types
function oauth_verify_rsa_sha1(message::String,certificate::String,signature::String)
    result = ccall((:oauth_verify_rsa_sha1,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),message,certificate,signature)
    if result == C_NULL
        error("oauth_verify_rsa_sha1 failed")
    end
    return bytestring(result)
end

#Only modified url type. How do you specific string array type in second argument?
function oauth_split_url_parameters(url::String,argv::Ptr{Ptr{Ptr{Uint8}}})
    result = ccall((:oauth_split_url_parameters,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Ptr{Ptr{Uint8}}}),url,argv)
    if result == C_NULL
        error("oauth_split_url_parameters failed")
    end
    return bytestring(result)
end

#Modified url and qesc types. How do you specific string array type in second argument?
function oauth_split_post_parameters(url::String,argv::Ptr{Ptr{Ptr{Uint8}}},usequeryescape::Integer)
    result = ccall((:oauth_split_post_paramters,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Ptr{Ptr{Uint8}}},Int16),url,argv,usequeryescape)
    if result == C_NULL
        error("oauth_split_post_paramters failed")
    end
    return bytestring(result)
end

#Modified first two types. Should argc be moved inside function, it is total number of elements in array?
function oauth_serialize_url(argc::Integer,start::Integer,argv::Ptr{Ptr{Uint8}})
    result = ccall((:oauth_serialize_url,LIBOAUTH),Ptr{Uint8},(Cint,Cint,Ptr{Ptr{Uint8}}),argc,start,argv)
    if result == C_NULL
        error("oauth_serialize_url failed")
    end
    return bytestring(result)
end

#Modified for Integer type
function oauth_serialize_url_sep(argc::Integer,start::Interger,argv::Ptr{Ptr{Uint8}},sep::Ptr{Uint8},mod::Integer)
    result = ccall((:oauth_serialize_url_sep,LIBOAUTH),Ptr{Uint8},(Cint,Cint,Ptr{Ptr{Uint8}},Ptr{Uint8},Cint),argc,start,argv,sep,mod)
    if result == C_NULL
        error("oauth_serialize_url_sep failed")
    end
    return bytestring(result)
end

#Modified for Integer type
function oauth_serialize_url_parameters(argc::Integer,argv::Ptr{Ptr{Uint8}})
    result = ccall((:oauth_serialize_url_parameters,LIBOAUTH),Ptr{Uint8},(Cint,Ptr{Ptr{Uint8}}),argc,argv)
    if result == C_NULL
        error("oauth_serialize_url_parameters")
    end
    return bytestring(result)
end

#What is use case to compare two strings for OAuth? Is this if you're building an API?
function oauth_cmpstringp(p1::Ptr{Void},p2::Ptr{Void})
    result = ccall((:oauth_cmpstringp,LIBOAUTH),Cint,(Ptr{Void},Ptr{Void}),p1,p2)
    if result == C_NULL
        error("oauth_cmpstringp failed")
    end
    return bytestring(result)
end

#Switched type to Integer and String. Like above, if argv just length of array, should we move inside function?
function oauth_param_exists(argv::Ptr{Ptr{Uint8}},argc::Integer,key::String)
    result = ccall((:oauth_param_exists,LIBOAUTH),Cint,(Ptr{Ptr{Uint8}},Cint,Ptr{Uint8}),argv,argc,key)
    if result == C_NULL
        error("oauth_param_exists failed")
    end
    return bytestring(result)
end

#Like above, if argcp just length of array, should we move inside function?
function oauth_add_param_to_array(argcp::Ptr{Cint},argvp::Ptr{Ptr{Ptr{Uint8}}},addparam::Ptr{Uint8})
    result = ccall((:oauth_add_param_to_array,LIBOAUTH),Void,(Ptr{Cint},Ptr{Ptr{Ptr{Uint8}}},Ptr{Uint8}),argcp,argvp,addparam)
    if result == C_NULL
        error("oauth_add_param_to_array failed")
    end
    return bytestring(result)
end

#Is this necessary? We don't need to worry about freeing memory, right?
function oauth_free_array(argcp::Ptr{Cint},argvp::Ptr{Ptr{Ptr{Uint8}}})
    result = ccall((:oauth_free_array,LIBOAUTH),Void,(Ptr{Cint},Ptr{Ptr{Ptr{Uint8}}}),argcp,argvp)
    if result == C_NULL
        error("oauth_free_array failed")
    end
    return bytestring(result)
end

#Is this necessary? Comparing two strings in constant time? Or is this if you're building an API? 
function oauth_time_independent_equals_n(a::Ptr{Uint8},b::Ptr{Uint8},len_a::Cint,len_b::Cint)
    result = ccall((:oauth_time_independent_equals_n,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Uint8},Cint,Cint),a,b,len_a,len_b)
    if result == C_NULL
        error("oauth_time_independent_equals_n failed")
    end
    return bytestring(result)
end

#Is this necessary? Comparing two strings in constant time? Or is this if you're building an API? 
#Docs say 'wrapper to oauth_time_independent_equals_n which calls strlen() for each argument', so we don't need both, right? (if any at all)
function oauth_time_independent_equals(a::Ptr{Uint8},b::Ptr{Uint8})
    result = ccall((:oauth_time_independent_equals,LIBOAUTH),Cint,(Ptr{Uint8},Ptr{Uint8}),a,b)
    if result == C_NULL
        error("oauth_time_independent_equals failed")
    end
    return bytestring(result)
end

#Instead of typealias for 'method', should we just make this a string?
#Pretty sure this is the MAIN function to make any API calls
function oauth_sign_url2(url::Ptr{Uint8},postargs::Ptr{Ptr{Uint8}},method::OAuthMethod,http_method::Ptr{Uint8},c_key::Ptr{Uint8},c_secret::Ptr{Uint8},t_key::Ptr{Uint8},t_secret::Ptr{Uint8})
    result = ccall((:oauth_sign_url2,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},Ptr{Ptr{Uint8}},OAuthMethod,Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),url,postargs,method,http_method,c_key,c_secret,t_key,t_secret)
    if result == C_NULL
        error("oauth_sign_url2 failed")
    end
    return bytestring(result)
end

function oauth_sign_array2_process(argcp::Ptr{Cint},argvp::Ptr{Ptr{Ptr{Uint8}}},postargs::Ptr{Ptr{Uint8}},method::OAuthMethod,http_method::Ptr{Uint8},c_key::Ptr{Uint8},c_secret::Ptr{Uint8},t_key::Ptr{Uint8},t_secret::Ptr{Uint8})
    result = ccall((:oauth_sign_array2_process,LIBOAUTH),Void,(Ptr{Cint},Ptr{Ptr{Ptr{Uint8}}},Ptr{Ptr{Uint8}},OAuthMethod,Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),argcp,argvp,postargs,method,http_method,c_key,c_secret,t_key,t_secret)
    if result == C_NULL
        error("oauth_sign_array2_process failed")
    end
    return bytestring(result)
end

function oauth_sign_array2(argcp::Ptr{Cint},argvp::Ptr{Ptr{Ptr{Uint8}}},postargs::Ptr{Ptr{Uint8}},method::OAuthMethod,http_method::Ptr{Uint8},c_key::Ptr{Uint8},c_secret::Ptr{Uint8},t_key::Ptr{Uint8},t_secret::Ptr{Uint8})
    result = ccall((:oauth_sign_array2,LIBOAUTH),Ptr{Uint8},(Ptr{Cint},Ptr{Ptr{Ptr{Uint8}}},Ptr{Ptr{Uint8}},OAuthMethod,Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),argcp,argvp,postargs,method,http_method,c_key,c_secret,t_key,t_secret)
    if result == C_NULL
        error("oauth_sign_array2 failed")
    end
    return bytestring(result)
end

#Modified Julia argument type
function oauth_body_hash_file(filename::String)
    result = ccall((:oauth_body_hash_file,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},),filename)
    if result == C_NULL
        error("oauth_body_hash_file failed")
    end
    return bytestring(result)
end

#Since first argument just length of string, should we move inside function? Modified Julia argument types
function oauth_body_hash_data(length::Integer,data::String)
    result = ccall((:oauth_body_hash_data,LIBOAUTH),Ptr{Uint8},(Cint,Ptr{Uint8}),length,data)
    if result == C_NULL
        error("oauth_body_hash_data failed")
    end
    return bytestring(result)
end

#Since first argument just length of string, should we move inside function? Modified len Julia argument type
function oauth_body_hash_encode(len::Integer,digest::Ptr{Cuchar})
    result = ccall((:oauth_body_hash_encode,LIBOAUTH),Ptr{Uint8},(Cint,Ptr{Cuchar}),len,digest)
    if result == C_NULL
        error("oauth_body_hash_encode failed")
    end
    return bytestring(result)
end

function oauth_sign_xmpp(xml::Ptr{Uint8},method::OAuthMethod,c_secret::Ptr{Uint8},t_secret::Ptr{Uint8})
    result = ccall((:oauth_sign_xmpp,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},OAuthMethod,Ptr{Uint8},Ptr{Uint8}),xml,method,c_secret,t_secret)
    if result == C_NULL
        error("oauth_sign_xmpp failed")
    end
    return bytestring(result)
end

#Since first argument just length of string, should we move inside function?
function oauth_encode_base64(size::Integer,source::String)
    #result = ccall((:oauth_sign_xmpp,LIBOAUTH),    )
    if result == C_NULL
        error("oauth_encode_base64 failed")
    end
    return bytestring(result)
end

#Does this make sense to include? When would we need to decode? Is this for if you are creating an API?
function oauth_decode_base64()
    error("Not yet implemented")
end

#Hope this is correct, test when on OSX machine
function oauth_url_escape(url::String)
    result = ccall((:oauth_url_escape,LIBOAUTH),Ptr{Uint8},(Ptr{Uint8},),url)
    if result == C_NULL
        error("oauth_url_escape failed")
    end
    return bytestring(result)
end

#Parse RFC3986 encoded 'string' back to unescaped version.
#Not sure of value of this?
function oauth_url_unescape()
    error("Not yet implemented")
end

#This 'url-escape strings and concatenate with '&' separator.' Could just use Julia for this?
function oauth_catenc()
    error("Not yet implemented")
end

end # module
