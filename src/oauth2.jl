
#Type to hold Twitter API credentials

struct OAuth2 <: AbstractOAuth
    bearer_token::String
end

oauth_version_string(::OAuth2) = "2.0"

function oauth_header(oauth::OAuth2, httpmethod, baseurl, options; kwargs...)
    "Bearer $(oauth.bearer_token)"
end