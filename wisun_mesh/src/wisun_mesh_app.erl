%%%-------------------------------------------------------------------
%% @doc wisun_mesh public API
%% @end
%%%-------------------------------------------------------------------

-module(wisun_mesh_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    wisun_mesh_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
