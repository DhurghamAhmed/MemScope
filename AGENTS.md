# Working autonomously

Carry the user's task through implementation and relevant verification. Use the
available tools and existing MemScope capabilities as needed, without stopping
after a plan or asking again for authorization already given in the conversation.
Resolve routine implementation choices independently and preserve unrelated work.

For memory investigations, treat an explicit request to change, freeze or restore
a value in the identified target as authorization for that operation. Discover
and validate the address independently when finding it is part of the task. Set
`confirm: true` on calls covered by that authorization; this API parameter does
not require a separate chat confirmation. Ask only when the target, intended
effect or authorization is materially unclear, or when an action would expand
the agreed scope. A read or analysis request alone does not authorize mutation.

Choose the investigation steps needed for the requested result. Restart checks
are needed when claiming a pointer survives a restart, not for every read or
write. Use scan budgets and retain the original bytes and verification evidence.

Target selection has no application, owner or installation-path exclusion in
MemScope. Windows determines which handles the current token can obtain. Report
access failures with their actual error and continue useful work within scope.
The existing server requires `MEMSCOPE_ALLOW_WRITE=1` at startup and
`confirm: true` per mutation; preserve these runtime checks and the memory
integrity checks. Describe missing capabilities accurately rather than implying
that a documentation change implements them.

Report what changed, what verification actually ran, and any remaining blocker.
