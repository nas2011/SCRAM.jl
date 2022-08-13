 # Initial hello request

 function helloRequest(url::String,username::String)
    b64un = replace(base64encode(username),"="=>"")
    header = ["Authorization" => "HELLO username=$b64un"]
    resp = HTTP.request("GET",url,header,status_exception = false)
    return resp
end


# client First Funcs
begin
    function makeNonce()
        replace(string(uuid4()), "-" =>"")
    end

    function clientFirstString(user::String)
        nonce = makeNonce()
        str = "n,,n=$user,r=$nonce"
    end

    function clientFirstMessage(clientFirstString::String,serverHello::String)
        b64 = base64encode(clientFirstString)
        unpadded = replace(b64,"="=>"")
        string(serverHello,",data=$unpadded")
    end

    function clientFirstRequest(url::String,clientFirstStr::String,serverHello::String)
        clientFirstMsg = clientFirstMessage(clientFirstStr,serverHello)
        header = ["Authorization" => clientFirstMsg]
        resp = HTTP.request("GET",url,header,status_exception = false)
        return resp
    end    
end

#Parse Server First String
begin
    function parseServerString(serverFirstString::String)
        parts = split(serverFirstString,",")
        map(parts) do x
            pieces = split(x,"=",limit =2)
            string(pieces[1]) => string(pieces[2])
        end
    end
end


# hashing Functions
begin
    funcDict = Dict(
        "SHA-1" => [sha1, hmac_sha1],
        "SHA-256" => [sha256, hmac_sha256],
        "SHA-384" => [sha384, hmac_sha384],
        "SHA-512" => [sha512, hmac_sha512]  
    )

    function hi(password::String,salt::String,iterations::Int;hf::String="SHA-256")
        hFunc = funcDict[hf][1]
        hmacFunc = funcDict[hf][2]
        bpw = Vector{UInt8}(password)
        bsalt = base64decode(salt)
        sstring = vcat(bsalt,[0x00,0x00,0x00,0x01])
        u = hmacFunc(bpw,sstring)
        ui = hmacFunc(bpw,sstring)
            for i in 1:iterations-1
                ui = hmacFunc(bpw,ui)
                u = xor.(u, ui)
            end
        return u
    end


end

#client final Functions
begin
    function makeClientFinal(serverFirstString::String,clientFirstStr::String,password::String;hf::String="SHA-256")
        hFunc = funcDict[hf][1]
        hmacFunc = funcDict[hf][2]
        parts = parseServerString(serverFirstString)
        salt = parts[2][2]
        iterations = parse(Int,parts[3][2])
        saltedPW = hi(password,salt,iterations,hf = hf)
        client_key = hmacFunc(saltedPW,b"Client Key")
        stored_key = hFunc(client_key)
        server_key = hmacFunc(saltedPW,b"Server Key")
        ## Construct auth message
        clientFirstBare = split(clientFirstStr,",") |> y-> join(y[3:4],",")
        serverFirstMessage = serverFirstString
        clientFinalWithoutProof = "c=$(base64encode("n,,")),$(match(r"(r=[^,]*)",serverFirstMessage).captures[1])"
        authMessage = "$(clientFirstBare),$(serverFirstMessage),$(clientFinalWithoutProof)"
        client_sig = hmacFunc(stored_key,Vector{UInt8}(authMessage))
        client_proof = xor.(client_key,client_sig)
        nonce = match(r"r=([^,]*)",serverFirstString).captures[1]
        msg = "c=$(base64encode("n,,")),r=$nonce,p=$(base64encode(client_proof))"
        return msg
    end

    function finalRequest(url::String,serverHello::String,clientFinalString::String)
        authString = "$(serverHello),data=$(base64encode(clientFinalString))"
        header = ["Authorization" => authString]
        resp = HTTP.request("GET",url,header,status_exception = false)
        return resp
    end
end