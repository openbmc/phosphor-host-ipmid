# Running Tests

## Setting Up Your Environment

For the purposes of this tutorial, we'll be setting up an environment in Docker.
Docker is handy because it's fairly portable, and won't interfere with the rest
of your machine setup. It also offers a strong guarantee that you're testing
the same way that others working on the project are. Finally, we can get away
with using the same Docker image that's run by the OpenBMC continuous
integration bot, so we have even more confidence that we're running relevant
tests the way they'd be run upstream.

### Install Docker

Installation of Docker CE (Community Edition) varies by platform, and may differ
in your organization. But the
[Docker Docs](https://docs.docker.com/v17.12/install/#cloud) are a good place to
start looking.

Check that the installation was successful by running `sudo docker run
hello-world`.

### Download OpenBMC Continuous Integration Image

You'll want a couple of different repositories, so start by making a place for
it all to go, and clone the CI scripts:

```shell
mkdir openbmc-ci-tests
cd openbmc-ci-tests
git clone https://github.com/openbmc/openbmc-build-scripts.git
```

### Add `phosphor-host-ipmid`

We also need to put a copy of the project you want to test against here. But
you've probably got a copy checked out already, so we're going to make a
*git worktree*. You can read more about those by running `git help worktree`,
but the basic idea is that it's like having a second copy of your repo - but the
second copy is in sync with your main copy, knows about your local branches, and
protects you from checking out the same branch in two places.

Your new worktree doesn't know about any untracked files you have in your main
worktree, so you should get in the habit of committing everything you want to
run tests against. However, because of the implementation of
`run-unit-test-docker.sh`, you can't run the CI with untracked changes anyways,
so this isn't the worst thing in the world. (If you make untracked changes in
your testing worktree, it's easy to update a commit with those.)

Note the placeholders in the following steps; modify the commands to match your
directory layout.

```shell
cd /my/dir/for/phosphor-host-ipmid
git worktree add /path/to/openbmc-ci-tests/phosphor-host-ipmid
```

Now, if you `cd /path/to/openbmc-ci-tests`, you should see a directory
`phosphor-host-ipmid/`, and if you enter it and run `git status` you will see
that you're likely on a new branch named `phosphor-host-ipmid`. This is just for
convenience, since you can't check out a branch in your worktree that's already
checked out somewhere else; you can safely ignore or delete that branch later.

However, Git won't be able to figure out how to get to your main worktree
(`/my/dir/for/phosphor-host-ipmid`), so we'll need to mount it when we run. Open
up `/path/to/openbmc-ci-tests/openbmc-build-scripts/run-unit-test-docker.sh` and
find where we call `docker run`, way down at the bottom. Add an additional
argument, remembering to escape the newline ('\'):

```shell
PHOSPHOR_IPMI_HOST_PATH="/my/dir/for/phosphor-host-ipmid"

docker run --blah-blah-existing-flags \
  -v ${PHOSPHOR_IPMI_HOST_PATH}:${PHOSPHOR_IPMI_HOST_PATH} \
  -other \
  -args
```

Then commit this, so you can make sure not to lose it if you update the scripts
repo:

```shell
cd openbmc-build-scripts
git add run-unit-test-docker.sh
git commit -m "mount phosphor-host-ipmid"
```

NOTE: There are other ways to do this besides a worktree; other approaches
trade the cruft of mounting extra paths to the Docker container for different
cruft:

You can create a local upstream:
```shell
cd openbmc-ci-tests
mkdir phosphor-host-ipmid
cd phosphor-host-ipmid
git init
cd /my/dir/for/phosphor-host-ipmid
git remote add /path/to/openbmc-ci-tests/phosphor-host-ipmid ci
git push ci
```
This method would require you to push your topic branch to `ci` and then `git
checkout` the appropriate branch every time you switched topics:
```shell
cd /my/dir/for/phosphor-host-ipmid
git commit -m "my changes to be tested"
git push ci
cd /path/to/openbmc-ci-tests/phosphor-host-ipmid
git checkout topic-branch
```

You can also create a symlink from your Git workspace into `openbmc-ci-tests/`.
This is especially not recommended, since you won't be able to work on your code
in parallel while the tests run, and since the CI scripts are unhappy when you
have untracked changes - which you're likely to have during active development.

## Building and Running

The OpenBMC CI scripts take care of the build for you, and run the test suite.
Build and run like so:

```shell
sudo WORKSPACE=$(pwd) UNIT_TEST_PKG=phosphor-host-ipmid \
  ./openbmc-build-scripts/run-unit-test-docker.sh
```

The first run will take a long time! But afterwards it shouldn't be so bad, as
many parts of the Docker container are already downloaded and configured.

## Reading Output

Your results will appear in
`openbmc-ci-tests/phosphor-host-ipmid/test/test-suite.log`, as well as being
printed to `stdout`. You will also see other `.log` files generated for each
test file, for example `sample_unittest.log`. All these `*.log` files are
human-readable and can be examined to determine why something failed

# Writing Tests

## Setting Up Your Environment

## Best Practices

## Sending for Review

# Reviewing Tests

## Best Practices

## Quickly Running At Home

# Credits

Thanks very much to Patrick Venture for his prior work putting together
documentation on this topic internal to Google.
