# SCRAM.jl

SCRAM.jl is a simple package for Salted Challenge Response Authentication Mechanism (SCRAM). For more information
on SCRAM see here [SCRAM RFC 5802](https://www.rfc-editor.org/rfc/rfc5802).

SCRAM.jl is a "bring your own string" implementation. That is to say, you are responsible for extracting the necessary components from each
server response and passing them as arguments. Within this package, a base64 encoded string is referred to as a message and a decoded
message is referred to as a string. It currently supports the following hashing mechanisms: SHA-1, SHA-256, SHA-384, SHA-512. It can
support any desired hashing mechanism by defining the necessary hash and hmac functions and adding them to the function dictionary.

Usage would look something like this:

```julia

    username = "user"
    password = "pencil"
    

    url = "your request url"

    # Send Hello message

    r = helloRequest(url,username) # HTTP.Messages.Response object from which you will extract your string of interest 

    serverHello = r.headers[8][2] |> string  # "scram handshakeToken=aaabbb, hash=SHA-256"

    # Construct and send client first request

    clientFirst = clientFirst(username)   # "n,,n=user,r=rOprNGfwEbeRWgbNEkqO"

    r1 = clientFirstRequest(url,clientFirst,serverHello) # HTTP.Messages.Response object from which you will extract your string of interest 

    # Construct and send client final request

    serverFirst = raw"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096" #You extracted this from r1

    clientFinal = makeClientFinal(serverFirst,clientFirst,password) # "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="

    r2 = finalRequest(url,serverHello,clientFinal) # HTTP.Messages.Response object from which you will extract your Auth Token
    
```

SCRAM.jl does not support channel binding, is not robust, and is a barebones solution at this point. It does work and could be made better.
It was built out of necessity to solve a specific problem quickly. Hopefully it can help you do the same, but a little quicker.