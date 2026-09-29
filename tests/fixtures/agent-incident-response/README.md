# agent-incident-response fixtures

Synthetic and inert. Nothing here runs or contacts a network; domains use `.invalid`.
`project/dot-git/` is renamed to `project/.git/` when the tests copy the tree,
because git refuses to track paths that contain a `.git` component.
Tokens are FAKE markers used to prove that output is redacted.
