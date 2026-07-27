# Non-blocking context procedures: the `async_m` monad

This is the implementation guide for `apps/smf_core/src/async_m.erl` and the way the context
`gen_statem` (`gtp_context`) runs multi-step procedures without blocking. Read it before writing an
async/await flow, converting a blocking external call, or touching the `async_pending` machinery.

## Why

`gtp_context` is a `gen_statem`. A procedure often has to talk to an external system and wait for the
answer: send a Gx CCR, wait for the CCA; send a PFCP modification, wait for the response. The obvious
way — a synchronous `gen_statem:call` or a selective `receive` — **blocks the whole FSM**: while it
waits it services no other message. That is a latent deadlock. Example: a mid-session Gx CCR-U blocks
the context; the PCRF, processing it, pushes an **RAR** for the same session; the context must answer
the RAR to make progress, but it is blocked in the `receive` and cannot — and if the PCRF gates its CCA
behind the RAA, neither ever completes. The same shape exists for PFCP session reports, a GTP Delete
Session arriving mid-procedure, and OCS-initiated RARs.

The fix is to never block the FSM: send the request, return to the event loop, and handle the reply
later as an ordinary message. But once you do that, a multi-step procedure can no longer live on one
call stack — the "what do I do after the reply" has to be captured explicitly. `async_m` is that
capture: it lets you write a procedure as a **linear `do`-block** that *reads* like blocking code while
the process stays fully responsive between steps.

## The monad

A monadic value is a function that threads the `gen_statem`'s two state components and yields a result:

```erlang
M :: fun((State, Data) -> {Result, State, Data})
Result :: {ok, term()} | {error, term()} | {await, ReqId, Conts}
```

`'>>='/2` (bind, driven by erlando's `do` transform) dispatches on the result of running the left side:

- `{ok, A}` — success; run the continuation `Fun(A)` against the threaded state.
- `{error, _}` — short-circuit; skip `Fun`, propagate the error unchanged (exception-like, no branching).
- `{await, ReqId, Conts}` — **suspend**: do *not* run `Fun`; prepend it to `Conts` and bubble the
  `await` up. Each enclosing bind prepends its own not-yet-run continuation, so `Conts` ends up as the
  reified "rest of the do-block", outermost-first.

Primitives:

- `return/1`, `fail/1`, `lift/1` — wrap a value / an error / a plain `ok|{ok,V}|{error,R}` term.
- `get_state/0`, `put_state/1`, `modify_state/1`, `get_data/0`, `put_data/1`, `modify_data/1` — read and
  update the two threaded components.
- `await/1` — the suspension point. `await(ReqId)` yields `{await, ReqId, []}`; the procedure resumes
  when a reply tagged `ReqId` arrives.
- `run/3` — run a value once (mostly for tests).

`resume(Conts, Reply)` reconstitutes a suspended computation: it reverses `Conts` (so the **innermost**
continuation — the step right after the `await` — receives the raw reply first) and folds outward. A
procedure may suspend any number of times; each `await` parks it again.

## The driver

Inside `gtp_context`:

- `run_async(M, OkFun, ErrFun, State, Data)` — run a procedure. On `{ok,V}` it calls `OkFun(V,S,D)`; on
  `{error,R}`, `ErrFun(R,S,D)`; on `{await, ReqId, Conts}` it **parks** `{Conts, OkFun, ErrFun}` under
  `ReqId` and returns to the event loop. `OkFun`/`ErrFun` return a native `gen_statem` result and are
  where the real FSM transition / caller reply happen.
- `handle_reply(ReqId, Reply, State, Data)` — when the matching reply arrives, take the parked entry,
  `resume(Conts, Reply)`, and hand it back to `run_async`. Returns `no_entry` if `ReqId` isn't parked.
- `async_apply(Fun)` — spawn a monitored worker that computes `Fun()` and sends
  `{'$async_reply', ReqId, {ok, Result}}` back; a crash surfaces as a tagged monitor `DOWN` mapped to
  `{error, {worker_down, Reason}}`. The generic "run something off-process and await it" primitive.

## The pending registry lives in the gen_statem **State**

The parked-computations map is `async_pending`, and it is a key in the **`State`** map (seeded by
`smf_context:init_state/0`), **not** in `Data`. This is load-bearing:

- Mutating `async_pending` (parking or draining a request) is a **state-term change**, and `gen_statem`
  re-delivers `postpone`d events only on a state change. So a serialization gate can `postpone`
  procedure-initiating events while a procedure is in flight and rely on the drain to re-fire them —
  with no separate "busy" flag to keep in sync (see "Serializing procedures").
- It is accessed with the `:=` operator everywhere (`#{async_pending := P} = S` to read,
  `S#{async_pending := ...}` to update) — never `maps:get/3` with a default. A `State` that lost the
  registry then crashes loudly instead of silently orphaning every other parked request. If you write a
  procedure step that replaces `State` with a fresh map literal, keep `async_pending`.

## Wiring into `gtp_context`

Two `info` clauses route replies into the driver (they guard on `async_pending` in `State`):

```erlang
handle_event(info, {'$async_reply', ReqId, Result}, #{async_pending := P} = State, Data)
  when is_map_key(ReqId, P) -> async_dispatch(ReqId, Result, State, Data);
handle_event(info, {{'$async_down', ReqId}, _MRef, process, _Pid, Reason},
             #{async_pending := P} = State, Data)
  when is_map_key(ReqId, P) -> async_dispatch(ReqId, {error, {worker_down, Reason}}, State, Data);
```

`async_dispatch/4` calls `async_m:handle_reply/4` inside a `try … catch throw:#ctx_err{} = E:St ->
handle_ctx_error(E, St, State, Data)`. This reinstates, per resumed segment, the same `#ctx_err{}` catch
the synchronous request path uses — see "Errors".

## Writing a procedure

The shape is: **read state → issue a request → `await` its reply → apply the result**. Split at each
`await`. Illustrative skeleton:

```erlang
handle_event(internal, {do_something, Arg}, State, Data) ->
    async_m:run_async(something_proc(Arg), fun something_ok/3, fun something_err/3, State, Data).

something_proc(Arg) ->
    do([async_m ||
           #{foo := Foo} <- async_m:get_data(),          %% read live Data (map-pattern bind is fine)
           ReqId <- async_m:lift(issue_request(Foo, Arg)),%% send it; issue_request returns {ok, ReqId}
           Reply <- async_m:await(ReqId),                 %% suspend until {'$async_reply', ReqId, _}
           Result <- async_m:lift(decode(Reply)),         %% {ok, _} | {error, #ctx_err{}} -> channel
           async_m:modify_data(_#{foo := new_foo(Result)})%% apply (cut: fun(D) -> D#{...} end)
       ]).

%% Return the threaded State as the NEXT state so the async_pending drain shows as a state change
%% (this re-fires anything the gate postponed while the procedure was parked).
something_ok(_V, State, Data) -> {next_state, State, Data}.
something_err(#ctx_err{} = E, State, Data) -> handle_ctx_error(E, [], State, Data).
```

Rules of the terminal funs:

- **Thread the State back.** The `State` passed to `OkFun`/`ErrFun` is the one the monad threaded
  through the procedure — after the reply, it has `async_pending` drained. Return it as `{next_state,
  State, Data}` (not `keep_state`, which would keep the *pre-drain* state and leave the registry stuck).
- `ErrFun` receives live `State`/`Data`, so it can build a protocol error reply (e.g. via
  `handle_ctx_error/4`) without the old trick of smuggling state into a thrown record.
- On the empty/no-op path (a procedure that never `await`s) `{next_state, State, Data}` with an
  unchanged `State` is just a no-op transition — fine.

## Serializing procedures (the gate)

Every procedure that touches shared session state (the PFCP `PCtx`, the Gx session, the bearer table)
must not overlap another: a second procedure reading that state *before* the first's resume writes it
back computes from stale state and the two clobber each other. Because the FSM is now responsive, that
overlap is possible — so serialize with a **coarse gate**: while `async_pending` is non-empty, postpone
procedure-initiating events.

```erlang
handle_event(internal, {some_procedure, _}, #{async_pending := P}, _Data)
  when map_size(P) =/= 0 -> {keep_state_and_data, [postpone]};
```

This reproduces the old blocking one-procedure-at-a-time behaviour non-blockingly: reentrant replies /
reports / RARs are still serviced during an `await` (that is the whole point), only new *procedure
starts* wait, and the `async_pending` drain (a state change) re-fires them. Gate every event class that
could start a procedure or mutate the shared state (GTP requests, procedure-starting internal events,
Gx/Gy RAR, ASR, the PFCP timer). The reference implementation is the PFCP `update_credits` work.

## Making an interface awaitable

To convert a blocking external call, add an async issue path to its client that (a) mints a `ReqId`
immediately and returns it, and (b) later delivers `{'$async_reply', ReqId, Reply}` to the calling
context process — reusing the info clause above, so no new dispatch wiring is needed. Keep the reply
transport's own timeout as the bound (do not add an `infinity` wait). The reference is
`smf_sx_node:send_request/2` (PFCP): it mints a `make_ref()` in the context, casts the request to the
node, and the node's response path sends the `'$async_reply'`.

## Errors: `throw(#ctx_err{})` coexistence

The codebase raises protocol errors with `throw(#ctx_err{...})` caught at the top of the request
handler. That works because a synchronous procedure lives on one stack. Once a procedure `await`s, no
single stack spans it, so a `throw` from a *resumed* step would escape the original catch. Two rules:

- `async_dispatch/4` reinstates the `throw:#ctx_err{}` catch around every resumed segment, so an
  existing throwing helper keeps working — the `#ctx_err{}` carries its own `context`/`tunnel`, so
  `handle_ctx_error` rebuilds the reply from the record. **You do not need to convert throwing helpers.**
- Do **not** rely on a lexical `try/catch` written *around* an `await` — it does not span the resumed
  continuation. Post-`await` error handling goes through the `#ctx_err{}` catch or the `{error,_}`
  channel (`lift/1` + the bind's short-circuit).

Convert a `throw` to the `{error,_}` channel only when a self-contained thrown record is insufficient —
chiefly to **compensate an already-committed side effect** on a *later* failure (e.g. tearing down a
PFCP session that established mid-procedure): there the channel hands `ErrFun` live `State`/`Data` to
clean up. This is per-procedure, never a blanket rewrite.

## Rules of thumb

- Never block the FSM once a session is live. If you're writing `gen_statem:call` or a selective
  `receive` for an external reply in a context procedure, use `async_m` instead.
- A procedure is a single `do([async_m || …])`, split at `await`s; issue requests one at a time.
- Terminal funs return `{next_state, State, Data}` to thread the drained registry back.
- Keep `async_pending` in `State`, access it with `:=`, never drop it.
- Every outstanding request must have a reply path (success, decode error, transport timeout, worker
  crash) — an unanswered `await` parks forever.

## Where the code is

- `apps/smf_core/src/async_m.erl` — the monad, driver, and `async_apply`.
- `apps/smf_core/test/async_m_SUITE.erl` — worked examples of every primitive (bind, resume ordering,
  multi-suspend, worker success/crash).
- `apps/smf_core/src/gtp_context.erl` — the `{'$async_reply'}`/`{'$async_down'}` info clauses,
  `async_dispatch/4`, and (in the PFCP work) the gate clauses and the `update_credits` procedure.
- `apps/smf_core/src/smf_context.erl` — `init_state/0` seeds `async_pending`.
