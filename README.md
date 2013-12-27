erl_ez_srp
===
Erlang srp lib

Use
---
```
srp_test() ->
  {public, Ser_Public, SerCompute} = 
      erl_ez_srp:set_server(sha256, <<"foo">>, <<"test">>, 2048, 128, 64),

  {public, Cli_Public, CliCompute} = 
      erl_ez_srp:set_client(sha256, <<"foo">>, <<"test">>, 2048, 128),
  
  {ok, Key} = SerCompute(Cli_Public),
  {ok, Key} = CliCompute(Ser_Public),
  {ok, Key}.
```

EXPORTS
---
##server

set_server(HashType, ID, PW)

set_server(HashType, ID, PW, PrimeGroup)

set_server(HashType, ID, PW, PrimeGroup, PrivLen, SaltLen) 

-> {public, {Salt, ServerPublic}, SerComputeKey/1}

###server curried function
SerComputeKey(ClientPublic) -> {ok, Key} | {error, bad_key}
  
---
##client

set_client(HashType, ID, PW)

set_client(HashType, ID, PW, PrimeGroup)

set_client(HashType, ID, PW, PrimeGroup, PrivLen) 

-> {public, ClientPublic, CliComputeKey/1}

###client curried function
CliComputeKey({Salt, ServerPublic}) -> {ok, Key} | {error, bad_key}
  
---
RFC 5054 Appendix B. Test passed