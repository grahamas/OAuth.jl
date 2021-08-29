
oauth_version_string(::T) where {T<:AbstractOAuth} = error("OAuth unimplemented for type $(T)")

"""
oauth_timestamp()

Returns current unix timestamp as String.

# Examples
```julia-repl
julia> oauth_timestamp()
"1512235859"
```
"""
function oauth_timestamp()
"$(round(Int, time()))"
end

"""
    oauth_nonce(length::Int)

Returns a random string of a given length.

# Examples
```julia-repl
julia> oauth_nonce(10)
"aQb2FVkrYi"
```
"""
function oauth_nonce(length::Int)
    randstring(length)
end

"""
    oauth_sign_hmac_sha1(message::String, signingkey::String)

Takes a message and signing key, converts to a SHA-1 digest, then encodes to base64.

# Examples
```jldoctest
julia> oauth_sign_hmac_sha1("foo", "bar")
"hdFVxV7ShqMAvRzxJN4I2H6RTzo="
```
"""
function oauth_sign_hmac_sha1(message::String, oauth::AbstractOAuth)
    base64encode(digest(MD_SHA1, message, oauth_signing_key(oauth)))
end

"""
    oauth_signature_base_string(httpmethod::String, url::String, parameterstring::String)

Returns encoded HTTP method, url and parameters.

# Examples
```jldoctest
julia> oauth_signature_base_string("POST", "https://julialang.org", "foo&bar")
"POST&https%3A%2F%2Fjulialang.org&foo%26bar"
```
"""
function oauth_signature_base_string(httpmethod::String, url::String, parameterstring::String)
    "$(httpmethod)&$(encodeURI(url))&$(encodeURI(parameterstring))"
end

"""
    oauth_percent_encode_keys!(options::Dict)

Returns dict where keys and values are URL-encoded.

# Examples
```jldoctest
julia> oauth_percent_encode_keys!(Dict("key 1" => "value1", "key    2" => "value 2"))
Dict{String,String} with 2 entries:
  "key%20%20%20%202" => "value%202"
  "key%201"          => "value1"
```
"""
function oauth_percent_encode_keys!(options::Dict)
    #options encoded
    originalkeys = collect(keys(options))

    for key in originalkeys
        key_str = string(key)
        encoded_key = encodeURI(key_str)

        options[encoded_key] = encodeURI(options[key_str])
        if encodeURI(key_str) != key
            delete!(options, key_str)
        end
    end

    options
end

@deprecate(
    oauth_percent_encode_keys(options::Dict),
    oauth_percent_encode_keys!(options::Dict)
)



"""
    oauth_serialize_url_parameters(options::Dict)

Returns query string by concatenating dictionary keys/values.

# Examples
```jldoctest
julia> oauth_serialize_url_parameters(Dict("foo" => "bar", "foo 1" => "hello!"))
"foo=bar&foo 1=hello!"
```
"""
oauth_serialize_url_parameters(options::Dict) = join(
    ["$key=$(options[key])" for key in sort!(collect(keys(options)))],
    "&"
)



# See: https://github.com/randyzwitch/OAuth.jl/issues/3
"""
    encodeURI(s)

Convenience function for `HTTP.escapeuri`.

# Examples
```jldoctest
julia> encodeURI("hello, world!")
"hello%2C%20world%21"
```
"""
encodeURI(s) = HTTP.escapeuri(s)

"""
    encodeURI!(dict_of_parameters::Dict)

Mutates dict_of_parameters using `encodeURI` on strings.

# Examples
```jldoctest
julia> encodeURI!(Dict("iv" => 10, "s" => "value!"))
Dict{String,Any} with 2 entries:
  "iv" => 10
  "s"  => "value%21"
```
"""
function encodeURI!(dict_of_parameters::Dict)
    for (k, v) in dict_of_parameters
        if typeof(v) <: String
            dict_of_parameters[k] = encodeURI(v)
        end
    end
    return dict_of_parameters
end

@deprecate(
    encodeURI(dict_of_parameters::Dict),
    encodeURI!(dict_of_parameters::Dict)
)

"""
    oauth_body_hash_file(filename::String)

Returns `oauth_body_hash=` along with base64 encoded SHA-1 from input text file.

# Examples
```jldoctest
julia> oauth_body_hash_file(joinpath(Pkg.dir(), "OAuth/test/auth_body_hash_file.txt"))
"oauth_body_hash=CgqfKmdylCVXq1NV12r0Qvj2XgE="
```
"""
function oauth_body_hash_file(filename::String)
    open(filename) do fn
        oauth_body_hash_data(read(fn, String))
    end
end

"""
    oauth_body_hash_data(data::String)

Returns `oauth_body_hash=` along with base64 encoded SHA-1 from input.

# Examples
```jldoctest
julia> oauth_body_hash_data("Hello, World!")
"oauth_body_hash=CgqfKmdylCVXq1NV12r0Qvj2XgE="
```
"""
function oauth_body_hash_data(data::String)
    "oauth_body_hash=$(oauth_body_hash_encode(data))"
end

"""
    oauth_body_hash_encode(data::String)

Convenience function for SHA-1 and base64 encoding.

# Examples
```jldoctest
julia> oauth_body_hash_encode("julialang")
"Lsztg2byou89Y8lBoH3G8v3vjbw="
```
"""
function oauth_body_hash_encode(data::String)
        base64encode(digest(MD_SHA1, data))
end

function oauth_signing_key(oauth::AbstractOAuth)
    error("Signing key unimplemented for type $(typeof(oauth))")
end

function oauth_signature(base_string, oauth::AbstractOAuth, signature_method)
    if signature_method == "HMAC-SHA1"
        encodeURI(oauth_sign_hmac_sha1(base_string, oauth_signing_key(oauth)))
    else
        error("Unsupported OAuth signature method: $(signature_method)")
    end
end