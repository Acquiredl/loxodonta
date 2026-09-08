<!-- Drafts can come from anywhere (a person, an agent, a template). Prose on
     the front door (README, SECURITY, CONTRIBUTING, CHANGELOG,
     CODE_OF_CONDUCT) is the author's; see CONTRIBUTING, "The voice rule". -->

<!-- No top-level heading: this text becomes the pull request body. -->
<!-- markdownlint-disable-next-line MD041 -->
## What changed

One or two sentences on the behavior, not a restatement of the diff.

## Which README claim or ADR it touches

Name the claim or the ADR, or write "none".

## Tests run

The command and the count: `python -m unittest discover -s tests` (N tests, OK).

## Checker run

`python tools/house_check.py`: exit 0, or the findings and why they stand.
