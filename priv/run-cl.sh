#!/bin/bash

ERL_AFLAGS="+C multi_time_warp" \
	rebar3 shell \
		--setcookie secret \
		--sname "smf-$1" \
		--config "priv/dev-$1.config" \
		--apps smf $@
