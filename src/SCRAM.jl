module SCRAM

    using SHA, Base64, HTTP, UUIDs

    include("functions.jl")

    export
        helloRequest,
        clientFirstString,
        clientFirstRequest,
        makeClientFinal,
        finalRequest

end
