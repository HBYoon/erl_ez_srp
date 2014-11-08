-module(test).

-export([do_once/0, do_once/2, do_once/3, do_once/4]).

do_once() ->
  do_once(<<"foo">>, <<"test_pw_value">>).
  
do_once(ID, PW) ->
  {ok, _} = do_once(ID, PW, 1024),
  {ok, _} = do_once(ID, PW, 1536),
  {ok, _} = do_once(ID, PW, 2048),
  {ok, _} = do_once(ID, PW, 3072),
  {ok, _} = do_once(ID, PW, 4096),
  {ok, _} = do_once(ID, PW, 6144),
  {ok, _} = do_once(ID, PW, 8192).
  
do_once(ID, PW, PrimeGroup) ->
  {ok, _} = do_once(ID, PW, PrimeGroup, sha),
  {ok, _} = do_once(ID, PW, PrimeGroup, sha256),
  {ok, _} = do_once(ID, PW, PrimeGroup, sha512).

do_once(ID, PW, PrimeGroup, HashType) ->
  {public, Ser_Public, SerCompute} = 
      erl_ez_srp:set_server(HashType, ID, PW, PrimeGroup, 128, 64),

  {public, Cli_Public, CliCompute} = 
      erl_ez_srp:set_client(HashType, ID, PW, PrimeGroup, 128),

  {ok, Key} = SerCompute(Cli_Public),
  {ok, Key} = CliCompute(Ser_Public).
  
  