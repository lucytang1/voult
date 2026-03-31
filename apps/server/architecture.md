logs in with (email + user_key)
return encrypted vault


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