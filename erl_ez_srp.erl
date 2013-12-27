%% @ HBYoon 2013
%% MIT License

%%(yy/mm/dd)
%% 13/12/27 - start


-module(erl_ez_srp).

% -export([test_5054/0]).
% -define(console(A), io:format("srp_test>> ~p~n", [A])).

% API
-export([
  set_server/2,
  set_server/3,
  set_server/4,
  set_server/6,
  
  set_client/2,
  set_client/3,
  set_client/4,
  set_client/5
]).
  
%==================================================================================
% srp api function
%==================================================================================
set_server(HashType, PW) ->
  set_server(HashType, <<0>>, PW, 2048, 128, 64).
  
set_server(HashType, ID, PW) ->
  set_server(HashType, ID, PW, 2048, 128, 64).
  
set_server(HashType, ID, PW, PrimeGroup) ->
  set_server(HashType, ID, PW, PrimeGroup, 128, 64).

set_server(HashType, ID, PW, PrimeGroup, PrivLen, SaltLen) ->
  {N, Gen, K} = ngk_gen(PrimeGroup, HashType),
  Ser_b = s_ran(PrivLen),
  Salt = s_ran(SaltLen),
  X = get_x(HashType, Salt, ID, PW),
  V = get_v(Gen, X, N),
  Ser_B = get_server_key(K, V, N, Gen, Ser_b),
  
  %% public key exchange point
  {public, {Salt, Ser_B}, fun(Cli_A)->
    U = get_u(HashType, N, Cli_A, Ser_B),
    
    server_secret (Cli_A, Ser_b, N, U, V)
  end}.
  

set_client(HashType, PW) ->
  set_client(HashType, <<0>>, PW, 2048, 128).
  
set_client(HashType, ID, PW) ->
  set_client(HashType, ID, PW, 2048, 128).
  
set_client(HashType, ID, PW, PrimeGroup) ->
  set_client(HashType, ID, PW, PrimeGroup, 128).
  
set_client(HashType, ID, PW, PrimeGroup, PrivLen) ->
  {N, Gen, K} = ngk_gen(PrimeGroup, HashType),
  Cli_a = s_ran(PrivLen),
  Cli_A = get_client_key(N, Gen, Cli_a),
  
  %% public key exchange point
  {public, Cli_A, fun({Salt, Ser_B}) ->
    X = get_x(HashType, Salt, ID, PW),
    U = get_u(HashType, N, Cli_A, Ser_B),
    
    client_secret(Ser_B, Cli_a, N, Gen, K, U, X)
  end}.
  
  
%==================================================================================
% srp internal function
%==================================================================================
pad_to(Width, Bin) ->
  PadBit = ((Width - size(Bin)) * 8),
  if 
    PadBit > 0 -> << 0: PadBit, Bin/binary >>;
    true       -> Bin
  end.

get_x(HashType, Salt, I, P) ->
  hash(HashType, [Salt, hash(HashType, [I, <<":">>, P])]).
  
get_v(Gen, X, N) ->
  pad_to(erlang:byte_size(N),pow_mod(Gen, X, N)).
  
get_k(HashType, N, G) ->
  hash(HashType, [N, (pad_to(erlang:byte_size(N), G))]).
  
get_u(HashType, N, Cli_A, Ser_B) ->
  SN = size(N),
  hash(HashType, [pad_to(SN, Cli_A), pad_to(SN, Ser_B)]).
  
get_server_key(K, V, N, Gen, Ser_b) ->
  bin(((uint(K) * uint(V)) + uint((pow_mod(Gen, Ser_b, N)))) rem uint(N)).
  
get_client_key(N, Gen, Cli_a) ->
  pow_mod(Gen, Cli_a, N).
  
server_secret (Cli_A, Ser_b, N, U, V) ->
  IntA = uint(Cli_A),
  IntN = uint(N),
  case (
    if (IntA rem IntN) =:= 0 -> false; true -> ok end
  ) of
    ok ->
      Ser_S = pow_mod(IntA * uint(pow_mod(V, U, N)), Ser_b, N),
      {ok, Ser_S};
    _ -> {error, bad_key}
  end.
  
client_secret (Ser_B, Cli_a, N, Gen, K, U, X)->
  IntB = uint(Ser_B),
  IntN = uint(N),
  IntU = uint(U),
  case {
    if (IntB rem IntN) =:= 0 -> false; true -> ok end, 
    if  IntU           =:= 0 -> false; true -> ok end
  } of
    {ok, ok} -> 
      Cli_S = pow_mod(
        IntB + IntN - (uint(K) * uint(pow_mod(Gen, X, N)) rem IntN),
        (uint(Cli_a) + IntU * uint(X)),
        N
      ),
      {ok, Cli_S};
    _ -> {error, bad_key}
  end.
  
%==================================================================================
% RFC 5054 N, g, k
%==================================================================================
  
ngk_gen(1024, HashType) ->
  N = <<16#EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3 : 1024>>,
  Gen = <<2>>,
  K = get_k(HashType, N, Gen),
  {N,Gen,K};
  
ngk_gen(1536, HashType) ->
  N = <<16#9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB : 1536>>, 
  Gen = <<2>>,
  K = get_k(HashType, N, Gen),
  {N,Gen,K};
  
ngk_gen(2048, HashType) ->
  N = <<16#AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73 : 2048>>,
  Gen = <<2>>,
  K = get_k(HashType, N, Gen),
  {N,Gen,K};
  
ngk_gen(3072, HashType) ->
  N = <<16#FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF : 3072>>,
  Gen = <<5>>,
  K = get_k(HashType, N, Gen),
  {N,Gen,K};
  
  
ngk_gen(4096, HashType) ->
  N = <<16#FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF : 4096>>,
  Gen = <<5>>,
  K = get_k(HashType, N, Gen),
  {N,Gen,K}.
  
  
%==================================================================================
% sugar function
%==================================================================================
  
pow_mod(B, E, M) ->
  crypto:mod_pow(B, E, M).
  
s_ran(L) ->
  crypto:strong_rand_bytes(L).
  
bin(N) ->
  binary:encode_unsigned(N).

uint(B) ->
  binary:decode_unsigned(B).

hash(Type, B) ->
  crypto:hash(Type, B).
  

%==================================================================================
% RFC 5054 Appendix B. Test
%==================================================================================
  
% test_5054() ->
  % KE = <<16#7556aa045aef2cdd07abaf0f665c3e818913186f : 160>>,
  % XE = <<16#94b7555aabe9127cc58ccf4993db6cf84d16c124 : 160>>,

  % VE = <<16#7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f1822223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a48cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04e058ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb : 1024>>,
  
  % Ser_B_E = <<16#bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58 : 1024>>,
  
  % Cli_A_E = <<16#61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b : 1024>>,
  
  % UE = <<16#ce38b9593487da98554ed47d70a7ae5f462ef019 : 160>>,
  
  % SE = <<16#b0dc82babcf30674ae450c0287745e7990a3381f63b387aaf271a10d233861e359b48220f7c4693c9ae12b0a6f67809f0876e2d013800d6c41bb59b6d5979b5c00a172b4a2a5903a0bdcaf8a709585eb2afafa8f3499b200210dcc1f10eb33943cd67fc88a2f39a4be5bec4ec0a3212dc346d7e474b29ede8a469ffeca686e5a : 1024>>,
  
  % HashType = sha,
  
  % I = <<"alice">>,
  % P = <<"password123">>,
  % Salt = <<16#beb25379d1a8581eb5a727673a2441ee : 128>>,
  % Cli_a = <<16#60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393 : 256>>,
  % Ser_b = <<16#e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20 : 256>>,
  
  % {N, Gen, K} = ngk_gen(1024, HashType),
  % X = get_x(HashType, Salt, I, P),
  % V = get_v(Gen, X, N),
  
  % Cli_A = get_client_key(N, Gen, Cli_a),
  % Ser_B = get_server_key(K, V, N, Gen, Ser_b),
  
  % U = get_u(HashType, N, Cli_A, Ser_B), 
  
  % {ok, Ser_S} = server_secret (Cli_A, Ser_b, N, U, V),
  % {ok, Cli_S} = client_secret(Ser_B, Cli_a, N, Gen, K, U, X),
  
  % KE = K,
  % XE = X,
  % VE = V,
  % Ser_B = Ser_B_E,
  % Cli_A = Cli_A_E,
  % U = UE,
  % Ser_S = Cli_S = SE,
  
  % ?console({ser_s, Ser_S}),
  % ?console({cli_s, Cli_S}),
  % ?console({se, SE}),
  % ok.