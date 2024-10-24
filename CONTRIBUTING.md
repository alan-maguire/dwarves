# Contributing

We welcome your contributions! There are multiple ways to contribute.

But before we describe these, it is worth describing the mechanics of
how releases are done, since these impact all forms of contribution.

## Release cycle

During development - which for v1.29 and later will follow the
Linux kernel release cycle - new features are added to the "next"
branch, and as we approach the release of a new Linux kernel,
intensive testing is done before moving those changes to the
"master" branch to cut a release.

In exceptional circumstances, a fix may be applied to the
master branch directly, and a sub-release cut, but this will
be done for critical fixes only.

As we approach the release deadline, the focus will turn to
fixing bugs and we may hold off on large feature changes as
a consequence.

## Ways to contribute - testing

Testing is really valuable, as pahole in particular has to work
across a wide variety of Linux kernels.  Running the tests
in the tests/ subdir is valuable, as is running

```
$ pahole -J -j --btf_features=default vmlinux
```

...on any kernels you have available that contain DWARF.

Running the tests is simply a matter of running

```
$ ./tests/tests
```

Tests can be run against a specific vmlinux (the vmlinux
on the system is used by default) via specifying vmlinux=,
for example

```
$ vmlinux=/path/2/vmlinux bash tests/tests

```

If failures are encountered, please get in touch. Ideally
making the vmlinux that triggered the failures available
is useful too.  Tests can be run in verbose mode by specifying
VERBOSE=1 in the environment, for example:

```
$ VERBOSE=1 ./tests/tests
```

## Ways to contribute - reviewing

Reviews are always welcome, and especially if you are planning
on contributing code yourself, starting with reviewing others
code is highly encouraged.

## Ways to contribute - documentation

We have a manual page for pahole, but similar manual pages
for pfunct for example would be useful too. Technical docs
on the implementation would be beneficial also.

## Ways to contribute - code

- We work via patches to dwarves@vger.kernel.org, not pull
  requests.  This is because the tools here have strong crossover
  with other aspects of Linux kernel development, so we keep
  the same processes where possible.
- Subscribe to dwarves@vger.kernel.org if you are going to
  contribute so you can keep up-to-date on features.
- Be mindful of the release logistics.  We won't ignore large
  patch series close to releases, but may defer applying them
  to promote stability.
- Be patient in waiting for review feedback, but if none has
  been received after a week it is okay to ping, but maintainers
  have other responsibilities so are not always in a position
  to reply immediately.
- We strongly encourage adding tests with new features.  The
  tests/ directory is modest now, but we hope to grow this
  significantly over time.

