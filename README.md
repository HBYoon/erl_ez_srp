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
  
  {ok, Secret} = SerCompute(Cli_Public),
  {ok, Secret} = CliCompute(Ser_Public),
  {ok, Secret}.
```

EXPORTS
---
##server

set_server(HashType, ID, PW)

set_server(HashType, ID, PW, PrimeGroup)

set_server(HashType, ID, PW, PrimeGroup, PrivLen, SaltLen) 

-> {public, {Salt, ServerPublic}, SerCompute/1}

###server curried function
SerCompute(ngk) -> {N_Prime, Generator, K_Multiplier}

SerCompute(ClientPublic) -> {ok, Secret} | {error, bad_key}
  
---
##client

set_client(HashType, ID, PW)

set_client(HashType, ID, PW, PrimeGroup)

set_client(HashType, ID, PW, PrimeGroup, PrivLen) 

-> {public, ClientPublic, CliCompute/1}

###client curried function
CliCompute(ngk) -> {N_Prime, Generator, K_Multiplier}

CliCompute({Salt, ServerPublicKey}) -> {ok, Secret} | {error, bad_key}
  
---
RFC 5054 Appendix B. Test passed