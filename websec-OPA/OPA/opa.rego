package barmanagement
default allow := false

import input.request.headers.Authorization


allow {
    token := get_bearer_token(input.request.headers.Authorization)
    [header, payload, signature] := io.jwt.decode(token)
    age := to_number(payload.age)
    role := payload.role[_]
    role == "customer"
    input.request.body.DrinkName == "Beer"
    age >= 16
    input.request.method == "POST"
    input.request.path != "/api/managebar"
}


allow {
    token := get_bearer_token(input.request.headers.Authorization)
    [header, payload, signature] := io.jwt.decode(token)
    role := payload.role[_]
    role == "customer" 
    input.request.body.DrinkName != "Beer"
    input.request.method == "POST"
    input.request.path != "/api/managebar"
}

allow {
    token := get_bearer_token(input.request.headers.Authorization)
    [header, payload, signature] := io.jwt.decode(token)
    role := payload.role[_]
    role == "bartender"                            
    input.request.method == "POST"
    input.request.path == "/api/managebar"
}

get_bearer_token(auth_header) = token {
    startswith(auth_header, "Bearer ")
    token := substring(auth_header, 7, -1)
}
