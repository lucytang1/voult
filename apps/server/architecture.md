logs in with (email + user_key)
return encrypted vaulta


Schema:
    
APIs:
/register
Request:
{
    email,
    user_key,
}

Response:
{
    email,
    vault,
    salt
}

/auth
Request:
{
    email,
    user_key
}

Response:
{
    email,
    vault,
    salt
}
