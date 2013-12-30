-module(test).

-export([srp_test/0]).

srp_test() ->
  {public, Ser_Public, SerCompute} = 
      erl_ez_srp:set_server(sha256, <<"foo">>, <<"test">>, 8192, 128, 64),

  {public, Cli_Public, CliCompute} = 
      erl_ez_srp:set_client(sha256, <<"foo">>, <<"test">>, 8192, 128),

  {ok, Key} = SerCompute(Cli_Public),
  {ok, Key} = CliCompute(Ser_Public),
  {ok, Key}.