
struct OAuth1a <: AbstractOAuth
    consumer_key::String
    consumer_secret::String
    token::String
    token_secret::String
end

oauth_version_string(::OAuth1a) = "1.0"

"""
    oauth_signing_key(oauth_consumer_secret::String, oauth_token_secret::String)

Returns a signing key based on a consumer secret and token secret.

# Examples
```jldoctest
julia> oauth_signing_key("foo", "bar")
"foo&bar"
```
"""
function oauth_signing_key(oauth::OAuth1a)
    "$(oauth.consumer_secret)&$(oauth.token_secret)"
end



"""
    function oauth_header(httpmethod, baseurl, options, oauth_consumer_key, oauth_consumer_secret, oauth_token, oauth_token_secret; oauth_signature_method = "HMAC-SHA1", oauth_version = "1.0")

Builds OAuth header, defaulting to OAuth 1.0. Function assumes `options` has already
been run through `encodeURI!`.

"""
function oauth_header(httpmethod, baseurl, options, oauth::OAuth1a; oauth_signature_method = "HMAC-SHA1")
    oauth_consumer_key = oauth.consumer_key
    oauth_consumer_secret = oauth.consumer_secret
    oauth_token = oauth.token
    oauth_token_secret = oauth.token_secret

    #keys for parameter string
    options["oauth_consumer_key"] = oauth_consumer_key
    options["oauth_nonce"] = oauth_nonce(32)
    options["oauth_signature_method"] = oauth_signature_method
    options["oauth_timestamp"] = oauth_timestamp()
    options["oauth_token"] = oauth_token
    options["oauth_version"] = oauth_version(oauth)

    #options encoded
    oauth_percent_encode_keys!(options)

    #Create ordered query string
    parameterstring = oauth_serialize_url_parameters(options)

    #Calculate signature_base_string
    signature_base_string = oauth_signature_base_string(uppercase(httpmethod), baseurl, parameterstring)

    #Calculate oauth_signature
    oauth_sig = oauth_signature(signature_base_string, oauth, oauth_signature_method)

    return "OAuth oauth_consumer_key=\"$(options["oauth_consumer_key"])\", oauth_nonce=\"$(options["oauth_nonce"])\", oauth_signature=\"$(oauth_sig)\", oauth_signature_method=\"$(options["oauth_signature_method"])\", oauth_timestamp=\"$(options["oauth_timestamp"])\", oauth_token=\"$(options["oauth_token"])\", oauth_version=\"$(options["oauth_version"])\""

end
